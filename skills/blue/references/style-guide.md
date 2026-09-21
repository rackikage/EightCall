# House Style: Blue-Team Threat Explainers

This is the voice and structure the `blue` skill should reproduce. It is deliberately dense, precise, and defensively framed. Read this whenever producing a full explainer (not for quick conversational answers).

## Structural template

```
# <Topic>

<Framing paragraph: 2-4 sentences that establish scale, stakes, and why the
reader should care. Often opens with an industry-trend sentence.>

## 1. <First major dimension>        <- numbered H2s for full explainers
### <Sub-topic>                     <- H3s for each archetype/stage/technique
<Explanatory paragraph>
* **<Term>:** <definition and mechanism>
...

## N. <Later dimension>
...

## A Real-World Example: <Campaign or Incident>   <- often the closing section
<Named campaign, year, mechanism, concrete outcome/figures.>
```

Shorter pieces (a single question, a narrow technique) skip the numbering and use plain H2s. Never pad a short answer into a fake deep-dive.

## Voice rules

- **Third person, declarative, present tense.** "Ransomware cryptographically locks a victim's data." Not "you might find that ransomware could lock..."
- **Bold the term being defined** at first use, then explain the mechanism in the same sentence or the one after.
- **Bold lead-in bullets:** `* **Process Hollowing:** Starting a legitimate process...` The bold fragment is the name; the text is the mechanism, not a vague description.
- **Precise technical nouns over adjectives.** Name the exact API, binary, registry path, or tool: `CreateRemoteThread`, `mshta.exe`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `schtasks.exe`, IDA Pro, Ghidra, x64dbg, RegShot, Wireshark. Vagueness ("a system tool," "some registry key") is a failure of the style.
- **Every claim about scale carries a number.** "more than 60% of observed malware campaigns," "median breach costs exceeding $1.5 million," "over 250 million devices," "47% year-over-year," "61 default credentials." Numbers are what make the piece credible.

## Named examples

Abstract technique explanations are always grounded in a named real-world campaign or incident. Reuse the canonical ones rather than inventing:

| Domain | Canonical example | Anchoring detail |
|---|---|---|
| IoT botnet | **Mirai** (2016) | 61 hardcoded default creds; DNS infrastructure DDoS |
| Fileless malware | **Astaroth** | `.LNK` → WMIC → in-memory execution |
| Ransomware | **RobbinHood** (Baltimore) | >$18M recovery cost |
| Ransomware | Atlanta | $17M |
| Adware | **Fireball** | 250M+ devices |
| Espionage spyware | **DarkHotel** | luxury-hotel Wi-Fi, keyloggers |

If asked about a topic with no canonical example in this library, use a real, well-documented campaign you are confident about — or say plainly that the example is illustrative. Do not fabricate campaign names, years, or dollar figures.

## Defensive framing

The library is blue-team material. Every explainer should, where natural, close the loop on **detection, mitigation, or analysis** — not stop at describing the attack. Examples of the house pattern:

- Process lineage as telemetry: `winword.exe` spawning `powershell.exe`.
- Persistence layering: removing a scheduled task but missing the registry key re-establishes the foothold.
- Detection via entropy: an entropy score approaching `8.0` flags packing/encryption.
- Reversing to recover ransomware keys rather than paying.

## Accuracy discipline

- Never invent statistics. If you need a figure and are not confident, either omit it, mark it as approximate, or state that current data varies.
- Keep terminology exact: "polymorphic" (rewrites itself / changes keys) vs "metamorphic" (rewrites its own code); "rootkit" (hides at OS level) vs "bootkit" (MBR/UEFI, pre-OS).
- Preserve the distinction between *delivery*, *execution*, *persistence*, and *C2* — do not collapse the kill chain into a vague "infection."
