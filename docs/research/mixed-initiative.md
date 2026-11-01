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

**Onnasch, Wickens, Li and Manzey, *Human Performance Consequences of Stages and Levels of Automation: An Integrated Meta-Analysis*, Human Factors 56(3), 2014, pp. 476–488, doi:10.1177/0018720813501549** ([open copy](https://depositonce.tu-berlin.de/items/7df9879f-d77b-4f2b-8760-f0e3d174ca67/full)) (*empirical*, meta-analysis of 18 experiments). As the degree of automation (DOA) rises, routine performance improves and workload falls somewhat. Performance when the automation fails gets worse, and so does situation awareness. The abstract states that "negative consequences of automation seem to be most likely when DOA moved across a critical boundary … between automation supporting information analysis and automation supporting action selection". The studies used laboratory tasks rather than real operators.

MIRA rule: the agent's autonomy stops at that boundary. It may acquire and analyse evidence. Decision and action selection are never automated, at any autonomy level.

**Jiang and Arkin, *Mixed-Initiative Human-Robot Interaction: Definition, Taxonomy, and Survey*, IEEE SMC 2015, pp. 954–961, doi:10.1109/SMC.2015.174** ([paper](https://sites.cc.gatech.edu/ai/robot-lab/online-publications/Jiang_Arkin_SMC2015_Mixed-Initiative_HRI_Taxonomy.pdf)). Definition and taxonomy: mixed initiative is a collaboration strategy in which humans and agents take or give up initiative as opportunities arise. The paper traces the concept in human–robot teams to Kortenkamp et al. (1997) and traded control.

MIRA rule: initiative is per entry. Either party may start an action, finding or question. Authority over decisions is not traded.

**Chen and Barnes, *Human-Agent Teaming for Multirobot Control: A Review of Human Factors Issues*, IEEE Transactions on Human-Machine Systems 44(1), 2014, pp. 13–29, doi:10.1109/THMS.2013.2293535.** Review. Trust, situation awareness, individual differences and the allocation of decision authority are the central human-factors issues when a person supervises agents.

**Chen et al., *Situation Awareness-Based Agent Transparency and Human-Autonomy Teaming Effectiveness*, Theoretical Issues in Ergonomics Science 19(3), 2018, doi:10.1080/1463922X.2017.1315750** ([article](https://www.tandfonline.com/doi/full/10.1080/1463922X.2017.1315750)) (review of the authors' experiments). The SAT model sets out three levels of agent transparency: (1) current actions and plans, (2) reasoning, (3) projected outcomes. In their studies, more transparency improved team performance and trust calibration. Teammate agents need *bidirectional* transparency: the agent must also understand the human's intent.

MIRA rule:
- SAT level 1 is the intent entry, level 2 is the finding with its citations, and level 3 is the proposal with its expected effect.
- In the other direction, the agent reads the operator's directives, decisions and question answers in the same log.

**Miller and Parasuraman, *Designing for Flexible Interaction Between Humans and Automation: Delegation Interfaces for Supervisory Control*, Human Factors 49(1), 2007, pp. 57–75, doi:10.1518/001872007779598037.** Architecture with empirical follow-ups. In *adaptable* automation the human delegates through a "playbook" of bounded tasks. It keeps flexibility while holding workload manageable, though a related study found the benefit disappeared as the number of supervised agents grew.

**Inagaki, *Situation-adaptive degree of automation for system safety*, IEEE RO-MAN 1993, doi:10.1109/ROMAN.1993.367716; and *Smart collaboration between humans and machines based on mutual understanding*, Cognition, Technology & Work 14, 2012, pp. 29–37.** Framework. In time-critical control, *machine-initiated* trading of authority, from the human to the automation, can improve safety.

MIRA rule: autonomy is *adaptable*, never *adaptive*. Only an operator directive changes it, and a directive is a bounded play with a budget and an expiry. Machine-initiated trading is rejected for MIRA: read-only investigation is not time-critical, and any authority the agent could seize would cross the Onnasch boundary.

## What goes wrong when automation takes over

**Bainbridge, *Ironies of Automation*, Automatica 19(6), 1983, pp. 775–779** ([paper](https://gwern.net/doc/sociology/technology/1983-bainbridge.pdf)). Analysis drawing on process-control and vigilance research. Automating most of a task leaves people with the hardest parts while their skills decay. People cannot sustain monitoring of rare abnormalities, and taking over in an emergency needs both manual and diagnostic skill.

MIRA rule: the operator stays the one who reaches the conclusion, working from the same evidence the agent sees. The agent does not reduce the operator to approving its summary.

**Strauch, *Ironies of Automation: Still Unresolved After All These Years*, IEEE Transactions on Human-Machine Systems 48(5), 2018, pp. 419–433, doi:10.1109/THMS.2017.2732506.** Review linking Bainbridge's ironies to automation-related accidents since 1983. It argues that the ironies remain unresolved despite the research they inspired, and identifies new ones.

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

## Security operations

**Alahmadi, Axon and Martinovic, *99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms*, USENIX Security 2022, pp. 2783–2800** ([paper](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi)) (*empirical*: a survey of 20 practitioners and a qualitative study of 21). Tools produce high false-positive rates that need manual validation, which leads to alarm burnout and desensitization. Most perceived false positives are "benign triggers", true alarms explained by legitimate local activity. Analysts want alarms that are reliable, explainable, analytical, contextual and transferable.

MIRA rule:
- Agent output is budgeted. Findings and questions consume the same per-session budget as actions, so the agent cannot flood the operator.
- Every finding carries its context as cited evidence, and a checked claim states exactly which result supports it.

**Sundaramurthy et al., *A Human Capital Model for Mitigating Security Analyst Burnout*, SOUPS 2015, pp. 347–359** ([paper](https://usenix.org/conference/soups2015/proceedings/presentation/sundaramurthy)) (*empirical*, anthropological fieldwork in SOCs). Burnout arises from a cycle in which analysts' skills, empowerment, creativity and growth go unused or unsupported.

MIRA rule, with Bainbridge: the agent supports the operator's investigation and does not take it over. The operator keeps the analytical work and the conclusion.

**Tilbury and Flowerday, *Automation Bias and Complacency in Security Operation Centers*, Computers 13(7), 2024, article 165, doi:10.3390/computers13070165** (scoping review of 48 articles), and ***Human-Automation Preferences in Security Operations Centers*, MWAIS 2025** ([abstract](https://aisel.aisnet.org/mwais2025/10)) (*empirical*, survey of 720 analysts). The review finds that SOC automation amplifies automation bias and complacency, so that analysts stop seeking confirming or contradicting information, and that human-in-the-loop support remains essential. The survey found preferences polarized: analysts "favored entirely human-driven or fully automated processes", with little desire for intermediate collaboration.

MIRA reading: this is evidence that operators may *prefer* the extremes. It does not show that the extremes *perform* better; the Onnasch meta-analysis points the other way on failure performance. MIRA lets the operator pick `manual`, or broad acquisition autonomy, but keeps decisions with the operator at every level. The stage 3 evaluation records preference separately from performance.

**Edelman et al., *Randomized Controlled Trials for Microsoft Copilot for Security*, SSRN 4648700, 2023–2024** ([paper](https://papers.ssrn.com/abstract=4648700)) (*empirical*, RCTs with about 150 novices and about 150 professionals; vendor-authored). With the assistant, novices produced more accurate and faster incident summaries, and professionals finished about 22% faster. These are a vendor's own measurements, with no independent replication found.

MIRA reading: assistance can help, and the effect may differ between novices and experts. The evaluation must stratify by expertise and must not rely on vendor figures.

**NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, April 2025** ([publication](https://csrc.nist.gov/pubs/sp/800/61/r3/final)). Guidance that maps incident response onto the six CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover) instead of the earlier linear cycle.

MIRA scope: a session supports detection and analysis on one host. Containment, eradication and recovery are state-changing and stay in Phase 5.

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

**Debenedetti et al., *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*, NeurIPS 2024 Datasets and Benchmarks** ([paper](https://arxiv.org/abs/2406.13352)) (*empirical*). An extensible environment with 97 tasks and 629 security test cases that measures an agent's utility and its security together. State-of-the-art models fail many tasks even without an attack.

**Nasr, Carlini et al., *The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections*, arXiv:2510.09023, 2025** ([paper](https://arxiv.org/abs/2510.09023)) (*empirical*). Adaptive attacks, including human-guided ones, bypassed 12 recent defenses with attack success above 90% for most, although the defenses had originally reported near-zero success.

**NIST AI 100-2 E2025, *Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations*, March 2025** ([publication](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)). The standard taxonomy, including direct and indirect prompt injection and the security of AI agents, and the limits of each mitigation.

MIRA rules:
- No detector, filter or "guardrail" is part of MIRA's security argument. Containment is architectural: the closed capability set, a broker the agent does not control, and a collector key the agent cannot use.
- Stage 2 measures utility and security together, AgentDojo-style. It tests with adaptive, human-red-team attacks, not only static injection strings.

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
- Several sources were preprints when checked: Feng et al., Beurer-Kellner et al., CaMeL and Nasr et al. Edelman et al. is vendor-authored. The practitioner frameworks (Willison, Meta, OWASP) are not peer-reviewed.
- Some evidence pulls against the design. Analysts may prefer the extremes of autonomy (Tilbury and Flowerday 2025), and adaptive automation can help in time-critical control (Inagaki). Both are recorded, along with the reasons the design differs.
