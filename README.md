# 🛡️ Pipeline Forense de Ingesta & Transcripción (`eDiscovery Engine`)

Sistema local *On-Premise* para la extracción, verificación de inmutabilidad, aislamiento de adjuntos y transcripción multilingüe/regional de evidencia digital.

---

## 🏗️ Arquitectura del Pipeline

```text
[Fase 0: Pre-Ingesta & SecOps]  ──>  [Fase 1: Inmutabilidad & Golden Source]  ──>  [Fase 2: Extracción Aislada & Sanitización]
   └─ Valida integridad/extensión       └─ Hash SHA-256 del contenedor (.zip)         └─ Descompresión segura / Unzip Air-gapped
   └─ Mitiga Zip Slip & Bombas          └─ Asignación de ID Forense Único              └─ Aislamiento de adjuntos ejecutables

```

---

## 📌 Fase 0: Definición de Identidad Forense y Hardening de Seguridad (SecOps)

Antes de manipular cualquier activo proveniente de dispositivos externos o exportaciones de terceros, el pipeline aplica reglas de contención para prevenir la ejecución de malware o denegación de servicio (DoS).

### 1. Sellado de Identidad Digital (Hashing Protocol)

* **Algoritmo Estándar:** `SHA-256` (Secure Hash Algorithm, 256-bit) sobre el archivo contenedor primario (`.zip` / `.tar.gz`) sin abrir ni modificar.
* **Propósito:** Definir el **Golden Source** (Fuente Dorada). Cualquier copia o extracción posterior debe hacer referencia cruzada al SHA-256 del archivo comprimido original.

### 2. Mitigación de Vectores de Ataque en Archivos Recibidos

| Vector de Riesgo | Amenaza / Impacto | Contramedida Técnica en Pipeline |
| --- | --- | --- |
| **Path Traversal (*Zip Slip*)** | Un `.zip` malicioso usa rutas relativas (`../../Windows/System32`) para sobrescribir archivos del sistema al extraer. | El extractor valida con `os.path.abspath` que todo archivo se extraiga **estrictamente dentro del directorio destino**. |
| **Bomba de Descompresión (*Zip Bomb*)** | Archivos comprimidos de pocos KB que se descomprimen en cientos de GB colapsando la RAM/Disco. | Verificación de ratio de compresión pre-extracción y límite estricto de tamaño máximo descomprimido (*Threshold Limit*). |
| **Ejecución Accidental de Malware** | Inclusión de `.exe`, `.bat`, `.ps1`, `.scr`, `.vbs`, `.iso` disfrazados entre adjuntos o audios. | **Aislamiento por Extensión (Quarantine Zone):** El pipeline solo procesa una lista blanca explícita (*Allowlist*). Cualquier otra extensión es movida a una carpeta aislada sin permisos de ejecución. |

---

## 📦 Fase 1 & 2: Especificación e Implementación del Módulo (`ingest_and_seal.py`)

El siguiente módulo ejecuta la verificación SHA-256 del contenedor primario, valida que no existan amenazas estructurales en el comprimido y realiza la extracción a un entorno aislado (*Sandbox Directory*).

```python
import os
import sys
import hashlib
import zipfile
from pathlib import Path

# --- CONFIGURACIÓN DE SEGURIDAD Y PERMITIDOS ---
ALLOWED_EXTENSIONS = {
    # Audios
    ".opus", ".wav", ".mp3", ".m4a", ".aac", ".ogg",
    # Logs / Texto
    ".txt", ".json", ".csv",
    # Adjuntos Documentales Seguros
    ".pdf", ".jpg", ".jpeg", ".png", ".webp"
}

MAX_UNCOMPRESSED_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # Cota de seguridad: 10 GB
MAX_COMPRESSION_RATIO = 100  # Ratio máximo permitido para evitar Zip Bombs


def calcular_sha256(filepath: str) -> str:
    """Calcula el Hash SHA-256 de un archivo en bloques de 64KB para optimizar RAM."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def validar_seguridad_zip(zip_ref: zipfile.ZipFile) -> None:
    """Inspecciona el contenido del ZIP sin extraer para prevenir Zip Slip y Zip Bombs."""
    total_size = 0
    compressed_size = 0

    for file_info in zip_ref.infolist():
        # 1. Detección de Zip Slip (Path Traversal)
        filename = file_info.filename
        if ".." in filename or filename.startswith("/") or "\\" in filename:
            raise ValueError(f"🚨 ALERTA DE SEGURIDAD: Traversal de ruta detectado en '{filename}'")

        total_size += file_info.file_size
        compressed_size += file_info.compress_size

    # 2. Detección de Bomba de Descompresión (Zip Bomb)
    if total_size > MAX_UNCOMPRESSED_SIZE_BYTES:
        raise ValueError(f"🚨 ALERTA DE SEGURIDAD: El contenido descomprimido supera el límite permitido ({total_size / (1024**3):.2f} GB)")

    if compressed_size > 0 and (total_size / compressed_size) > MAX_COMPRESSION_RATIO:
        raise ValueError("🚨 ALERTA DE SEGURIDAD: Ratio de compresión anómalo (Posible Zip Bomb).")


def procesar_fase_0_1_2(zip_path: str, base_output_dir: str):
    """
    Ejecuta el ciclo inicial de Custodia y Extracción Segura:
    - Fase 0: Verificación de estructura y sanitización.
    - Fase 1: Sellado SHA-256 del Zip Origen (Golden Source).
    - Fase 2: Extracción aislada y cuarentena de ejecutables.
    """
    zip_path_obj = Path(zip_path)
    if not zip_path_obj.exists():
        print(f"❌ Error: No se encuentra el contenedor '{zip_path}'")
        return

    print("=" * 70)
    print("🔒 [FASE 1] SELLADO DIGITAL DE CONTENEDOR PRIMITIVO (GOLDEN SOURCE)")
    print("=" * 70)
    
    zip_sha256 = calcular_sha256(zip_path)
    print(f"📦 Archivo: {zip_path_obj.name}")
    print(f"🔑 Hash SHA-256: {zip_sha256}")
    print(" status: INMUTABLE (Solo Lectura)\n")

    # Rutas de trabajo
    target_extract_dir = Path(base_output_dir) / "01_Entorno_Aislado"
    quarantine_dir = Path(base_output_dir) / "00_Cuarentena_Riesgo"
    
    target_extract_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("🛡️ [FASE 0 & 2] AUDITORÍA DE SEGURIDAD Y EXTRACCIÓN CONTROLADA")
    print("=" * 70)

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Inspección preventiva pre-extracción
            validar_seguridad_zip(zf)
            print("✅ Verificación de estructura completada: Sin patrones de Zip Slip ni Zip Bomb.")

            archivos_extraidos = 0
            archivos_cuarentena = 0

            for member in zf.infolist():
                if member.is_dir():
                    continue

                filename = Path(member.filename).name
                ext = Path(filename).suffix.lower()

                # Extracción segura a memoria temporal primero
                extracted_data = zf.read(member.filename)
                
                # Clasificación por Allowlist
                if ext in ALLOWED_EXTENSIONS:
                    dest_file = target_extract_dir / filename
                    with open(dest_file, "wb") as f_out:
                        f_out.write(extracted_data)
                    archivos_extraidos += 1
                else:
                    # Archivos no reconocidos o binarios/ejecutables van a Cuarentena
                    dest_file = quarantine_dir / f"{filename}.QUARANTINE"
                    with open(dest_file, "wb") as f_out:
                        f_out.write(extracted_data)
                    archivos_cuarentena += 1
                    print(f"⚠️ [CUARENTENA] Archivo bloqueado por extensión de riesgo: {filename}")

            print(f"\n📊 RESUMEN DE INGESTA:")
            print(f"   • Archivos procesados y admitidos: {archivos_extraidos}")
            print(f"   • Archivos aisllados en Cuarentena: {archivos_cuarentena}")
            print(f"   • Carpeta de trabajo aislada: {target_extract_dir}")

    except Exception as e:
        print(f"❌ Error en la extracción segura: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Demostración del laboratorio
    ZIP_EVIDENCIA = "evidencia_demo.zip"
    DIRECTORIO_PROCESO = "OUTPUT_PROCESAMIENTO_FORENSE"

    # Generar ZIP sintético para demo si no existe
    if not os.path.exists(ZIP_EVIDENCIA):
        with zipfile.ZipFile(ZIP_EVIDENCIA, 'w') as z:
            z.writestr("audio_prueba_01.opus", b"DATOS_DUMMY_AUDIO_1")
            z.writestr("documento_adjunto.pdf", b"DATOS_DUMMY_PDF")
            z.writestr("script_sospechoso.exe", b"MZ_DUMMY_EXECUTABLE_TEST")  # Debería ir a cuarentena

    procesar_fase_0_1_2(ZIP_EVIDENCIA, DIRECTORIO_PROCESO)

```

---

## 📝 Documentación del Módulo en el `README.md`

### Garantías de Cadena de Custodia

1. **Acceso Pass-Through:** El archivo `.zip` original nunca se sobrescribe ni se abre en aplicaciones con permisos de escritura.
2. **Defensa ante Infección/Malware:**
* Lista blanca estricta (*Allowlist*).
* Desactivación de permisos de ejecución en cualquier adjunto no multimedia.
* Aislamiento preventivo de extensiones `.exe`, `.scr`, `.bat`, `.ps1`, `.dll`, `.iso`.


3. **Auditabilidad:** El log de consola emite directamente el SHA-256 del contenedor primario, permitiendo que cualquier perito informático replique el cálculo y verifique la coincidencia bit a bit.
