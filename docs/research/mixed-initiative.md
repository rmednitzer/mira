# Research basis: mixed-initiative operation

This note records the research that MIRA's shared workspace ([ADR 0015](../adr/0015-shared-mixed-initiative-workspace.md)) is designed against. Each entry states what the source establishes, how strong that evidence is, and the design rule MIRA takes from it. Sources were checked on 2026-11-01. Frameworks and guidelines are design knowledge, not measured guarantees; only the entries marked *empirical* report controlled studies, and those studies used other tasks than Linux incident investigation. Nothing here shows that MIRA's design works; [ADR 0015's evaluation stage](../adr/0015-shared-mixed-initiative-workspace.md#stage-3-evaluation) is what would.

## What "mixed-initiative" means here

Mixed-initiative interaction lets either party, the operator or the AI agent, take the initiative: start an action, raise a finding, ask a question, or propose a next step. Each party contributes what it is best at, under rules both can see. Autonomy is not one setting for the whole system. It is set separately for each kind of function, bounded, and revocable by the operator at any time.

## Interaction principles

**Horvitz, *Principles of Mixed-Initiative User Interfaces*, CHI '99, pp. 159–166** ([paper](https://www.erichorvitz.com/chi99horvitz.pdf)). Framework, illustrated by the LookOut system. Twelve critical factors. The first four are value-added automation, uncertainty about the user's goals, the user's attention in timing services, and the expected value of acting under uncertainty. The paper states the other eight as:
- (5) employing dialog to resolve key uncertainties, "considering the costs of potentially bothering a user needlessly"
- (6) allowing efficient direct invocation and termination
- (7) minimizing the cost of poor guesses about action and timing
- (8) scoping precision of service to match uncertainty: "a preference for doing less but doing it correctly"
- (9) efficient agent–user collaboration to refine results
- (10) socially appropriate behaviour
- (11) maintaining working memory of recent interactions
- (12) continuing to learn by observing

The paper's decision model chooses between acting, asking or doing nothing by comparing expected utilities against thresholds, which designers or users can set directly.

MIRA rules:
- The agent can ask the operator a question as well as act (5). Questions queue for the operator to read rather than interrupting (3).
- The operator can start or stop the agent at any time (6).
- Findings say how certain they are, and an unverified inference is never presented as a checked fact (8).
- The operator can refine or reject any agent result (9).
- The session log is the shared working memory both parties refer to by entry number (11).
- Learning (12) is out of scope until it can be evaluated.

**Klein, Woods, Bradshaw, Hoffman and Feltovich, *Ten Challenges for Making Automation a "Team Player" in Joint Human-Agent Activity*, IEEE Intelligent Systems 19(6), 2004, doi:10.1109/MIS.2004.74** ([summary](https://blog.acolyer.org/2020/01/10/ten-challenges-for-automation/)). Framework from joint-activity research. A team player must:
- keep common ground with the other party
- be predictable and make its intentions interpretable
- be directable when priorities shift
- signal when it is failing
- keep the cost of coordination low

MIRA rules:
- The session log is the common ground.
- The agent announces its intent before it acts.
- Operator directives take effect immediately.
- An agent step that fails is recorded as such, never dropped.
- The operator reads pending items when they choose to, so coordination costs little.

**Johnson et al., *Coactive Design: Designing Support for Interdependence in Joint Activity*, Journal of Human-Robot Interaction 3(1), 2014, pp. 43–69, doi:10.5898/JHRI.3.1.Johnson** ([author copy](https://jeffreymbradshaw.net/publications/20101008_CoactiveDesign.pdf)). Framework and method, demonstrated in the DARPA Virtual Robotics Challenge. The paper argues that autonomy should be shaped by the interdependence between the parties, through three properties:
- **observability:** making one's status and knowledge visible
- **predictability:** being reliable enough that others can plan around one's actions
- **directability:** being able to direct the other party and to be directed by it

MIRA rule: every entry names its principal and the entries it rests on. The operator can see what the agent did and why, can predict what it may do next from the visible autonomy level and budget, and can redirect it with a directive.

**Amershi et al., *Guidelines for Human-AI Interaction*, CHI 2019, doi:10.1145/3290605.3300233** ([project](https://www.microsoft.com/en-us/research/project/guidelines-for-human-ai-interaction/)). Eighteen guidelines distilled from more than 160 recommendations and validated in four phases, grouped by when they apply: at first, during interaction, when the AI is wrong, and over time. Guidelines 15–18 include granular feedback, conveying the consequences of user actions, global controls and notifying users of changes. The authors say the guidelines are design support, not a checklist.

MIRA rules:
- Before a session starts, it states what the agent may do and how well it is expected to do it.
- The operator can stop the agent globally.
- Each finding takes its own accept or reject decision.
- Changes to the agent's autonomy are logged as entries.

## Levels and types of autonomy

**Parasuraman, Sheridan and Wickens, *A Model for Types and Levels of Human Interaction with Automation*, IEEE Trans. SMC-A 30(3), 2000, pp. 286–297, doi:10.1109/3468.844354.** Framework. Automation applies separately to four functions:
- information acquisition
- information analysis
- decision and action selection
- action implementation

Each function can be automated at a different level. Human-performance consequences are the primary evaluation criterion, with reliability and the cost of consequences secondary. The model does not prescribe what to automate.

MIRA rule: the workspace sets autonomy separately for each function. The agent may acquire evidence on its own initiative, within a budget. It may analyse and propose. Decisions belong to the operator. No state-changing action exists.

**Feng, McDonald and Zhang, *Levels of Autonomy for AI Agents*, arXiv:2506.12469, 2025** ([paper](https://arxiv.org/abs/2506.12469)). Framework, not yet peer-reviewed. It defines five user roles: operator, collaborator, consultant, approver and observer. It argues that autonomy is a design decision separate from capability, and proposes autonomy certificates.

MIRA rule: the agent's autonomy level is an explicit, operator-signed setting that is recorded in the session and checked on every action, not a property inferred from the model.

## What goes wrong when automation takes over

**Bainbridge, *Ironies of Automation*, Automatica 19(6), 1983, pp. 775–779** ([paper](https://gwern.net/doc/sociology/technology/1983-bainbridge.pdf)). Analysis drawing on process-control and vigilance research. Automating most of a task leaves people with the hardest parts while their skills decay. People cannot sustain monitoring of rare abnormalities, and taking over in an emergency needs both manual and diagnostic skill.

MIRA rule: the operator stays the one who reaches the conclusion, working from the same evidence the agent sees. The agent does not reduce the operator to approving its summary.

**Endsley and Kiris, *The Out-of-the-Loop Performance Problem and Level of Control in Automation*, Human Factors 37(2), 1995, pp. 381–394** (*empirical*). Higher automation lowered situation awareness through passive processing, and slowed decisions after the automation failed. The level of operator control moderated the loss. Intermediate levels are often cited as preserving awareness, although findings vary.

MIRA rule: autonomy defaults to an intermediate level, in which the agent may gather evidence and the operator decides. A model failure leaves a usable session the operator can continue alone.

**Lee and See, *Trust in Automation: Designing for Appropriate Reliance*, Human Factors 46(1), 2004, pp. 50–80** ([PubMed](https://pubmed.ncbi.nlm.nih.gov/15151155/)). Review and conceptual model. Reliance should be calibrated to actual capability; misuse is over-reliance and disuse is under-reliance. Trust guides reliance but does not fully determine it.

MIRA rule: show what the agent can and cannot check. A machine-checked claim and an inference are labelled differently, so trust can follow the label.

## Over-reliance on AI advice

**Bansal et al., *Does the Whole Exceed its Parts? The Effect of AI Explanations on Complementary Team Performance*, CHI 2021, doi:10.1145/3411764.3445717** (*empirical*, three datasets). Human–AI teams outperformed either alone. State-of-the-art explanations added nothing beyond simply showing the AI's confidence. Explanations raised acceptance of AI recommendations whether or not they were correct.

**Buçinca, Malaya and Gajos, *To Trust or to Think: Cognitive Forcing Functions Can Reduce Overreliance on AI*, PACM HCI 5(CSCW1), 2021, article 188** ([paper](https://arxiv.org/abs/2102.09692)) (*empirical*, N = 199). Interventions that make people engage analytically reduced over-reliance compared with explanations alone. Participants liked them least, and over-reliance was not eliminated.

**Vasconcelos et al., *Explanations Can Reduce Overreliance on AI Systems During Decision-Making*, PACM HCI 7(CSCW1), 2023, article 129, doi:10.1145/3579605** ([paper](https://arxiv.org/abs/2212.06823)) (*empirical*, five studies, N = 731). People weigh the cost of checking the AI against the cost of relying on it. Explanations reduced over-reliance when they made verification cheaper.

MIRA rules:
1. **No persuasive narrative.** An agent finding is a claim from a closed vocabulary, with a confidence label and citations to session entries. Free-text notes are allowed, but they are bounded, labelled as unchecked and never the basis of a check.
2. **Cheap verification.** Each citation points to an exact signed document already in the session. For claims that the evidence can settle, MIRA checks the claim against the cited outcome when the entry is appended. The operator sees "checked" rather than having to repeat the work.
3. **Optional forcing.** An operator can record their own assessment before reading the agent's findings. This is opt-in, because forcing functions cost satisfaction.

**EU AI Act, Regulation (EU) 2024/1689, Article 14** ([text](https://euaiact.com/article/14)). Law. Human oversight of high-risk systems must let the overseer remain aware of the tendency to over-rely on the system's output ("automation bias"), interpret it correctly, decide not to use it, and intervene or stop it. MIRA is not classified as a high-risk system here. The article names the same failure modes as the studies above.

MIRA rule: a stop, an override and a rejection are first-class entries.

## AI-agent security

**Greshake et al., *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*, arXiv:2302.12173, 2023** ([paper](https://arxiv.org/abs/2302.12173)) (*empirical attacks on deployed systems*). Content that the model retrieves can carry instructions, so the line between data and instructions disappears.

For MIRA, host evidence is that content. Journal unit names, dpkg version strings and service states are attacker-influenceable (TB2), and an agent reads them.

**Willison, *The Lethal Trifecta for AI Agents*, 2025** ([post](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)), and **Meta, *Agents Rule of Two*, 2025** ([post](https://ai.meta.com/blog/practical-ai-agent-security/)). Practitioner frameworks. An agent session should not combine all three of:
- processing untrusted input
- access to private data or sensitive systems
- changing state or communicating externally

Meta frames this as a supplement to least privilege, not a replacement, and notes that a human approval step can make a transition between configurations safe.

For MIRA, the agent always has the first two: it reads untrusted host evidence, and that evidence is private. The third must therefore be absent. The agent gets no state-changing capability and no network channel. A hosted model is itself an external channel, which is why host data goes only to a local model and hosted models see synthetic or public sessions only (existing policy). Any future write needs the operator's approval.

**OWASP, *LLM06:2025 Excessive Agency*** ([text](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). Practitioner guidance:
- minimal tools, and granular tools instead of open-ended ones such as a shell or URL fetching
- minimal downstream permissions
- acting under the user's own identity
- independent human approval for high-impact actions

MIRA rule: the agent's whole action set is the closed list of read-only templates, with validated arguments, run by `mira` under the operator's account. There is no shell, no fetch, and no way for the agent to add capabilities.

**Debenedetti et al., *Defeating Prompt Injections by Design (CaMeL)*, arXiv:2503.18813, 2025** ([paper](https://arxiv.org/abs/2503.18813)), and **Beurer-Kellner et al., *Design Patterns for Securing LLM Agents against Prompt Injections*, arXiv:2506.08837, 2025** ([paper](https://arxiv.org/abs/2506.08837)) (*empirical*, AgentDojo). Separate control flow from untrusted data. Attach provenance and capabilities to values and enforce policy outside the model. Patterns such as action-selector (untrusted results handled only by reference), dual LLM, map-reduce and context minimization, and CaMeL's code-then-execute, keep injected content from choosing consequential actions. CaMeL solved 77% of AgentDojo tasks with provable security, against 84% undefended.

MIRA rules:
- Enforcement happens in `mira`, never in the model: the closed action set, argument validation, autonomy and budget checks, and claim checks.
- Every entry carries provenance (principal, signature, sequence).
- Injected content can at worst make the agent post a wrong but labelled claim, or propose something the operator must approve. It cannot widen the agent's capabilities.

## AI in incident diagnosis

**Chen et al., *Automatic Root Cause Analysis via Large Language Models for Cloud Incidents (RCACopilot)*, EuroSys 2024** ([paper](https://arxiv.org/abs/2305.15778)) (*empirical*, one year of Microsoft incidents). A system that collects diagnostics and has an LLM predict a root-cause category reached about 0.77 micro-F1. Useful, but wrong roughly a quarter of the time, in a setting with rich, curated handlers.

MIRA reading: model diagnoses are useful but fallible. They must stay checkable proposals, not conclusions, which is consistent with the over-reliance findings.

## Limits of this basis

- The empirical studies used decision tasks such as classification, mazes and quizzes, and cloud incidents. None studied a shared Linux investigation workspace, so effect sizes do not transfer.
- The design rules are hypotheses until MIRA's own matched-task evaluation (ADR 0015 stage 3) measures correctness, time, evidence access and over-reliance against an operator-only baseline.
- Two sources (Feng et al., Beurer-Kellner et al.) were preprints when checked. The practitioner frameworks (Willison, Meta, OWASP) are not peer-reviewed.
