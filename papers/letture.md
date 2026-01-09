# Appunti e pensieri vari

# DeGPT: Optimizing Decompiler Output with LLM

## fonte da "Reference paper NoGoToNoCry"

[https://www.ndss-symposium.org/wp-content/uploads/2024-401-paper.pdf](https://www.ndss-symposium.org/wp-content/uploads/2024-401-paper.pdf)

framework che usa LLM per rendere l’output dei decompiler più leggibile (nomi variabili + commenti sensati).
approccio **a 3 ruoli**:

- **Referee (arbitro)** -> individua parti poco chiare/migliorabili.
- **Advisor (consigliere)** -> propone miglioramenti (nomi, struttura, commenti).
- **Operator (esecutore)** -> applica le modifiche verificando che il comportamento del codice resti lo stesso.
  Per garantire che la semantica non cambi usa **MSSC**.
  Risultati: meno carico cognitivo, output più leggibile, qualità superiore rispetto ai metodi esistenti.

## Takeaways

1. Definire criteri di umanità e complessità partendo dai difetti classici dei decompiler (es. nomi brutti, codice ridondante, zero commenti).
2. Non usare un singolo prompt -> meglio multi-step
3. metriche usate (forse spunto)

# DecLLM: LLM-Augmented Recompilable Decompilation for Enabling Programmatic Use of Decompiled Code

## fonte da keyword su google scholar

[https://dl.acm.org/doi/pdf/10.1145/3728958](https://dl.acm.org/doi/pdf/10.1145/3728958)

Parla anche di DeGPT (non voluto lol)

Parla di come funziona la decompilazione in C, background
esempi di prompt
static reparing(?) non so se potrebbe essere un problema ma voglio fidarmi dei decompilatori
controllo su allucinazioni in loop

# LLM4Decompile: Decompiling Binary Code with Large Language Models

## fonte da keyword su google scholar

[https://arxiv.org/pdf/2403.05286](https://arxiv.org/pdf/2403.05286)

LLM come sostituzione dei decompiler specializzato per la re-execution dopo il disassemblamento del binario
interessante discorso sul training e sul fine tuning con guidelines e best practices
humaneval e exebench come valutazione codice generato da LLM

# Refining Decompiled C Code with Large Language Models

## fonte da keyword su google scholar

[https://arxiv.org/pdf/2310.06530](https://arxiv.org/pdf/2310.06530)

molto simile agli altri, creano framework DecGPT -> uguale sputato a DecLLM

NUOVA
https://aclanthology.org/2025.findings-acl.1194.pdf
