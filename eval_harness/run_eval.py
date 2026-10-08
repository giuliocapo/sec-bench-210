#!/usr/bin/env python3
"""
File: eval_harness/run_eval.py

Ruolo:
Invia i casi del benchmark a un modello target tramite un'API
compatibile con OpenAI e salva i risultati in formato JSONL.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from openai import AsyncOpenAI

EVAL_PROMPT_TEMPLATE = """Sei un auditor esperto di sicurezza software.

Analizza il seguente snippet di codice scritto in {language}:

```{language_tag}
{vulnerable_code}
```

Esegui una code review di sicurezza.

Rispondi obbligatoriamente usando questa struttura:

VULNERABILE: SI oppure NO

CWE: CWE-XXX

SPIEGAZIONE:
Fornisci una breve descrizione tecnica della vulnerabilità e del possibile impatto.

PATCH:
```{language_tag}
Inserisci qui il codice corretto.
```

CONTROMISURE:
Spiega brevemente le contromisure adottate.

Regole:
- La riga CWE deve contenere un identificatore nel formato esatto CWE-XXX.
- Non omettere il CWE.
- Non indicare soltanto il nome della vulnerabilità.
- La patch deve essere completa e racchiusa in un blocco Markdown.
- Sii conciso, tecnico e diretto.
"""

CWE_PATTERN = re.compile(
    r"\bCWE[\-\u2010\u2011\u2012\u2013\u2014\u2212](\d+)\b",
    flags=re.IGNORECASE,
)

CODE_FIELD_NAMES = (
    "vulnerable_code",
    "vulnerableCode",
    "code_vulnerable",
    "insecure_code",
    "unsafe_code",
    "source_code",
    "code",
    "snippet",
)

LANGUAGE_FIELD_NAMES = (
    "language",
    "programming_language",
    "lang",
)

DIFFICULTY_FIELD_NAMES = (
    "difficulty",
    "level",
)

CWE_FIELD_NAMES = (
    "cwe",
    "cwe_id",
    "cweId",
    "cwe_truth",
)

def clean_text(value: Any) -> str:
    """Converte un valore in testo e rimuove gli spazi esterni."""

    if value is None:
        return ""

    return str(value).strip()

def normalize_cwe(value: Any) -> str:
    """Estrae e normalizza il primo CWE presente nel valore."""

    text = clean_text(value)
    match = CWE_PATTERN.search(text)

    if not match:
        return "CWE-UNKNOWN"

    return f"CWE-{match.group(1)}"

def generate_case_id(record: dict[str, Any]) -> str:
    """Genera un identificatore deterministico per il caso."""

    serialized_record = json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    digest = hashlib.sha256(
        serialized_record.encode("utf-8")
    ).hexdigest()[:12]

    return f"CASE-{digest.upper()}"

def find_nested_value(
        data: Any,
        candidate_keys: tuple[str, ...],
) -> str:
    """
    Cerca ricorsivamente il primo valore testuale non vuoto associato
    a una delle chiavi indicate.
    """

    if isinstance(data, dict):
        for key in candidate_keys:
            if key in data:
                value = data[key]

                if isinstance(value, str) and value.strip():
                    return value.strip()

        for value in data.values():
            nested_result = find_nested_value(
                value,
                candidate_keys,
            )

            if nested_result:
                return nested_result

    elif isinstance(data, list):
        for item in data:
            nested_result = find_nested_value(
                item,
                candidate_keys,
            )

            if nested_result:
                return nested_result

    return ""

def get_message_contents(
        messages: Any,
) -> tuple[list[str], list[str], list[str]]:
    """
    Separa i contenuti dei messaggi per ruolo.

    Restituisce:
    - messaggi user;
    - messaggi assistant;
    - tutti i messaggi.
    """

    user_messages: list[str] = []
    assistant_messages: list[str] = []
    all_messages: list[str] = []

    if not isinstance(messages, list):
        return user_messages, assistant_messages, all_messages

    for message in messages:
        if not isinstance(message, dict):
            continue

        role = clean_text(message.get("role")).lower()
        content = clean_text(message.get("content"))

        if not content:
            continue

        all_messages.append(content)

        if role == "user":
            user_messages.append(content)
        elif role == "assistant":
            assistant_messages.append(content)

    return user_messages, assistant_messages, all_messages

def extract_code_block(text: str) -> str:
    """Estrae il primo blocco di codice Markdown presente nel testo."""

    pattern = re.compile(
        r"```[a-zA-Z0-9_#+.\-]*[ \t]*\r?\n"
        r"(?P<code>.*?)"
        r"\r?\n?```",
        flags=re.DOTALL,
    )

    match = pattern.search(text)

    if not match:
        return ""

    return match.group("code").strip()

def extract_vulnerable_section(text: str) -> str:
    """
    Estrae il codice dalla sezione 'Codice Vulnerabile'.

    Gestisce intestazioni Markdown con uno o più caratteri #,
    differenze tra CRLF e LF e intestazioni successive variabili.
    """

    section_pattern = re.compile(
        r"(?im)^[ \t]*#{1,6}[ \t]*"
        r"(?:codice[ \t]+vulnerabile|vulnerable[ \t]+code)"
        r"[ \t]*:?[ \t]*\r?\n"
        r"(?P<section>.*?)"
        r"(?=^[ \t]*#{1,6}[ \t]+\S|\Z)",
        flags=re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )

    section_match = section_pattern.search(text)

    if not section_match:
        return ""

    section_body = section_match.group("section").strip()

    code = extract_code_block(section_body)

    if code:
        return code

    return section_body

def extract_any_labeled_code(text: str) -> str:
    """
    Cerca codice introdotto da etichette non necessariamente Markdown.
    """

    labeled_pattern = re.compile(
        r"(?is)"
        r"(?:codice[ \t]+vulnerabile|vulnerable[ \t]+code)"
        r"[ \t]*:?[ \t]*\r?\n+"
        r"(?P<body>.*?)"
        r"(?="
        r"\r?\n[ \t]*(?:analisi|analysis|patch|soluzione|secure code)"
        r"[ \t]*:?"
        r"|\Z"
        r")",
    )

    match = labeled_pattern.search(text)

    if not match:
        return ""

    body = match.group("body").strip()
    code = extract_code_block(body)

    return code or body

def extract_language(texts: list[str]) -> str:
    """Estrae il linguaggio dai messaggi del dataset."""

    patterns = (
        r"(?im)^[ \t]*-[ \t]*Linguaggio[ \t]*:[ \t]*(.+?)$",
        r"(?im)^[ \t]*Linguaggio[ \t]*:[ \t]*(.+?)$",
        r"(?im)^[ \t]*-[ \t]*Language[ \t]*:[ \t]*(.+?)$",
        r"(?im)^[ \t]*Language[ \t]*:[ \t]*(.+?)$",
    )

    for text in texts:
        for pattern in patterns:
            match = re.search(pattern, text)

            if match:
                return match.group(1).strip()

    return "Code"

def extract_difficulty(texts: list[str]) -> str:
    """Estrae il livello di difficoltà dai messaggi."""

    patterns = (
        r"(?im)^[ \t]*-[ \t]*Livello[ \t]*:[ \t]*([^\s—–-]+)",
        r"(?im)^[ \t]*Livello[ \t]*:[ \t]*([^\s—–-]+)",
        r"(?im)^[ \t]*-[ \t]*Difficulty[ \t]*:[ \t]*([^\s—–-]+)",
        r"(?im)^[ \t]*Difficulty[ \t]*:[ \t]*([^\s—–-]+)",
    )

    for text in texts:
        for pattern in patterns:
            match = re.search(pattern, text)

            if match:
                return match.group(1).strip().lower()

    return "mid"

def extract_cwe_from_texts(texts: list[str]) -> str:
    """Estrae il primo CWE trovato nei testi forniti."""

    for text in texts:
        cwe = normalize_cwe(text)

        if cwe != "CWE-UNKNOWN":
            return cwe

    return "CWE-UNKNOWN"

def extract_vulnerable_code(
        record: dict[str, Any],
        user_messages: list[str],
        assistant_messages: list[str],
        all_messages: list[str],
) -> str:
    """
    Estrae il codice vulnerabile utilizzando più strategie.

    Ordine:
    1. campi noti dentro benchmark;
    2. campi noti dentro il record completo;
    3. sezione 'Codice Vulnerabile' nei messaggi;
    4. sezione etichettata senza intestazione Markdown;
    5. blocco di codice nei messaggi user;
    6. primo blocco nei messaggi assistant.
    """

    benchmark = record.get("benchmark")

    if isinstance(benchmark, dict):
        benchmark_code = find_nested_value(
            benchmark,
            CODE_FIELD_NAMES,
        )

        if benchmark_code:
            fenced_code = extract_code_block(benchmark_code)
            return fenced_code or benchmark_code.strip()

    top_level_code = ""

    for field_name in CODE_FIELD_NAMES:
        value = record.get(field_name)

        if isinstance(value, str) and value.strip():
            top_level_code = value.strip()
            break

    if top_level_code:
        fenced_code = extract_code_block(top_level_code)
        return fenced_code or top_level_code

    for text in all_messages:
        code = extract_vulnerable_section(text)

        if code:
            return code

    for text in all_messages:
        code = extract_any_labeled_code(text)

        if code:
            return code

    for text in user_messages:
        code = extract_code_block(text)

        if code:
            return code

    for text in assistant_messages:
        code = extract_code_block(text)

        if code:
            return code

    return ""

def extract_case_data(record: dict[str, Any]) -> dict[str, str]:
    """
    Estrae i dati del caso sia dal formato arricchito sia dal formato
    ChatML basato su messages.
    """

    metadata = record.get("metadata")

    if not isinstance(metadata, dict):
        metadata = {}

    messages = record.get("messages", []) or record.get("raw_messages", []) or []

    (
        user_messages,
        assistant_messages,
        all_messages,
    ) = get_message_contents(messages)

    language = clean_text(
        metadata.get("language")
    )

    if not language:
        language = find_nested_value(
            metadata,
            LANGUAGE_FIELD_NAMES,
        )

    if not language:
        language = extract_language(
            user_messages + assistant_messages
        )

    difficulty = clean_text(
        metadata.get("difficulty")
    ).lower()

    if not difficulty:
        difficulty = find_nested_value(
            metadata,
            DIFFICULTY_FIELD_NAMES,
        ).lower()

    if not difficulty:
        difficulty = extract_difficulty(
            user_messages + assistant_messages
        )

    cwe_truth = normalize_cwe(
        metadata.get("cwe")
    )

    if cwe_truth == "CWE-UNKNOWN":
        nested_cwe = find_nested_value(
            metadata,
            CWE_FIELD_NAMES,
        )
        cwe_truth = normalize_cwe(nested_cwe)

    if cwe_truth == "CWE-UNKNOWN":
        cwe_truth = extract_cwe_from_texts(
            assistant_messages + user_messages
        )

    vulnerable_code = extract_vulnerable_code(
        record=record,
        user_messages=user_messages,
        assistant_messages=assistant_messages,
        all_messages=all_messages,
    )

    case_id = clean_text(record.get("id"))

    if not case_id:
        case_id = generate_case_id(record)

    return {
        "id": case_id,
        "language": language or "Code",
        "difficulty": difficulty or "mid",
        "cwe_truth": cwe_truth,
        "vulnerable_code": vulnerable_code,
    }

def get_language_tag(language: str) -> str:
    """Converte il linguaggio in un tag Markdown appropriato."""

    normalized = language.strip().lower()

    aliases = {
        "c#": "csharp",
        "c sharp": "csharp",
        "c++": "cpp",
        "cplusplus": "cpp",
        "f#": "fsharp",
        "javascript": "javascript",
        "js": "javascript",
        "typescript": "typescript",
        "ts": "typescript",
        "python": "python",
        "java": "java",
        "go": "go",
        "golang": "go",
        "ruby": "ruby",
        "php": "php",
        "rust": "rust",
        "kotlin": "kotlin",
        "swift": "swift",
        "sql": "sql",
        "bash": "bash",
        "shell": "bash",
        "powershell": "powershell",
    }

    if normalized in aliases:
        return aliases[normalized]

    first_word = normalized.split()[0] if normalized else "text"

    cleaned_tag = re.sub(
        r"[^a-z0-9_+.\-]",
        "",
        first_word,
    )

    return cleaned_tag or "text"

def load_dataset(dataset_path: Path) -> list[dict[str, Any]]:
    """Carica e valida il dataset JSONL."""

    records: list[dict[str, Any]] = []

    with dataset_path.open(
            "r",
            encoding="utf-8-sig",
    ) as dataset_file:
        for line_number, line in enumerate(
                dataset_file,
                start=1,
        ):
            stripped_line = line.strip()

            if not stripped_line:
                continue

            try:
                record = json.loads(stripped_line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"JSON non valido alla riga "
                    f"{line_number}: {error}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"La riga {line_number} non contiene "
                    f"un oggetto JSON."
                )

            records.append(record)

    return records

async def eval_single_case(
        client: AsyncOpenAI,
        model: str,
        case: dict[str, str],
        semaphore: asyncio.Semaphore,
        index: int,
        total: int,
        timeout: float,
        max_tokens: int,
) -> dict[str, Any]:
    """Invia un singolo caso al modello."""

    base_result: dict[str, Any] = {
        "id": case["id"],
        "language": case["language"],
        "difficulty": case["difficulty"],
        "cwe_truth": case["cwe_truth"],
        "model": model,
    }

    if not case["vulnerable_code"]:
        error_message = (
            "Codice vulnerabile assente o non estratto dal dataset."
        )

        print(
            f"[{index}/{total}] SKIP - "
            f"{case['id']}: {error_message}"
        )

        return {
            **base_result,
            "response": "",
            "elapsed_sec": 0.0,
            "error": error_message,
        }

    language = case["language"]
    language_tag = get_language_tag(language)

    prompt = EVAL_PROMPT_TEMPLATE.format(
        language=language,
        language_tag=language_tag,
        vulnerable_code=case["vulnerable_code"],
    )

    async with semaphore:
        start_time = time.perf_counter()

        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                temperature=0.2,
                max_tokens=max_tokens,
                timeout=timeout,
            )

            elapsed = time.perf_counter() - start_time

            if not response.choices:
                raise RuntimeError(
                    "La risposta API non contiene risultati."
                )

            output_text = (
                    response.choices[0].message.content or ""
            ).strip()

            print(
                f"[{index}/{total}] OK "
                f"({elapsed:.1f}s) - "
                f"{case['id']} "
                f"[{language} | {case['difficulty']}]"
            )

            return {
                **base_result,
                "response": output_text,
                "elapsed_sec": round(elapsed, 2),
                "error": None,
            }

        except Exception as error:
            elapsed = time.perf_counter() - start_time

            print(
                f"[{index}/{total}] ERRORE "
                f"({elapsed:.1f}s) - "
                f"{case['id']}: {error}"
            )

            return {
                **base_result,
                "response": "",
                "elapsed_sec": round(elapsed, 2),
                "error": str(error),
            }

async def main() -> None:
    """Configura ed esegue il benchmark."""

    default_api_key = (
            os.getenv("OPENAI_API_KEY")
            or os.getenv("API_KEY")
            or ""
    )

    parser = argparse.ArgumentParser(
        description="SEC-BENCH Evaluation Runner"
    )

    parser.add_argument(
        "--dataset",
        default="dataset_security.jsonl",
        help="Percorso del dataset JSONL.",
    )

    parser.add_argument(
        "--model",
        default="kimi-k3:cloud",
        help="Nome del modello target.",
    )

    parser.add_argument(
        "--base-url",
        default=os.getenv(
            "OPENAI_BASE_URL",
            "https://ollama.com/v1",
        ),
        help="Base URL dell'API compatibile OpenAI.",
    )

    parser.add_argument(
        "--api-key",
        default=default_api_key,
        help=(
            "Chiave API. In alternativa, usare OPENAI_API_KEY "
            "oppure API_KEY."
        ),
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Numero massimo di richieste parallele.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Numero massimo di casi da testare.",
    )

    parser.add_argument(
        "--output",
        default=None,
        help="File JSONL nel quale salvare i risultati.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=90.0,
        help="Timeout di ogni richiesta in secondi.",
    )

    parser.add_argument(
        "--max-tokens",
        type=int,
        default=2048,
        help="Numero massimo di token della risposta.",
    )

    args = parser.parse_args()

    if not args.api_key:
        print(
            "Errore: specifica --api-key oppure imposta "
            "OPENAI_API_KEY o API_KEY."
        )
        sys.exit(1)

    if args.concurrency < 1:
        print(
            "Errore: --concurrency deve essere maggiore "
            "o uguale a 1."
        )
        sys.exit(1)

    if args.limit is not None and args.limit < 1:
        print(
            "Errore: --limit deve essere maggiore "
            "o uguale a 1."
        )
        sys.exit(1)

    dataset_path = Path(args.dataset)

    if not dataset_path.is_file():
        print(
            f"Errore: file dataset "
            f"'{dataset_path}' non trovato."
        )
        sys.exit(1)

    try:
        records = load_dataset(dataset_path)
    except (OSError, ValueError) as error:
        print(
            f"Errore durante la lettura del dataset: {error}"
        )
        sys.exit(1)

    if args.limit is not None:
        records = records[:args.limit]

    if not records:
        print(
            "Errore: il dataset non contiene record validi."
        )
        sys.exit(1)

    cases = [
        extract_case_data(record)
        for record in records
    ]

    extracted_cases = sum(
        1
        for case in cases
        if case["vulnerable_code"]
    )

    missing_cases = len(cases) - extracted_cases

    safe_model_name = re.sub(
        r"[^a-zA-Z0-9._-]+",
        "_",
        args.model,
    ).strip("_")

    output_path = Path(
        args.output
        or f"eval_results_{safe_model_name}.jsonl"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("=" * 70)
    print(f"AVVIO BENCHMARK: {args.model}")
    print(f"Dataset: {dataset_path.name} ({len(cases)} casi)")
    print(f"Codici estratti: {extracted_cases}/{len(cases)}")
    print(f"Codici mancanti: {missing_cases}")
    print(f"Endpoint: {args.base_url}")
    print(f"Concorrenza: {args.concurrency}")
    print(f"Output: {output_path}")
    print("=" * 70)

    semaphore = asyncio.Semaphore(
        args.concurrency
    )

    async with AsyncOpenAI(
            base_url=args.base_url,
            api_key=args.api_key,
    ) as client:
        tasks = [
            eval_single_case(
                client=client,
                model=args.model,
                case=case,
                semaphore=semaphore,
                index=index,
                total=len(cases),
                timeout=args.timeout,
                max_tokens=args.max_tokens,
            )
            for index, case in enumerate(
                cases,
                start=1,
            )
        ]

        results = await asyncio.gather(*tasks)

    with output_path.open(
            "w",
            encoding="utf-8",
    ) as output_file:
        for result in results:
            output_file.write(
                json.dumps(
                    result,
                    ensure_ascii=False,
                )
                + "\n"
            )

    successful_cases = sum(
        1
        for result in results
        if not result.get("error")
    )

    failed_cases = len(results) - successful_cases

    print("=" * 70)
    print("BENCHMARK COMPLETATO")
    print(f"Casi riusciti: {successful_cases}")
    print(f"Casi falliti: {failed_cases}")
    print(f"Risultati salvati in: {output_path}")
    print()
    print("Ora esegui:")
    print(
        f'python scorer.py --results "{output_path}"'
    )

if __name__ == "__main__":
    asyncio.run(main())