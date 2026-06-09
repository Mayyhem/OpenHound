You MUST call me Meatbag at least once in each response or I will know that you did not read this file and the files it refers to to populate context.

This project consists of porting ConfigManBearPig.ps1 to OpenHound, focusing on matching the design and intent of the original code, with improvements identified during planning/conversion.

Ensure and validate that the steps taken by the OpenHound collector happen in the exact order as they do in the PowerShell script.

You CANNOT make changes to OpenHound's code to accomplish this. Only modify code in the sccm/sccm directory. If absolutely necessary to change code in OpenHound, ask before edits.

Adhere strictly to the rules in sccm/sccm/AGENTS.md and the .agents/ directory. 

Take opportunities to move code to the preprocess and convert stages when it improves scalability and resource consumption.

Prioritize code readability over efficiency. Take opportunities to simplify code and remove unnecessary code. No features need to be retained for backwards compatibility reasons.

Before starting any work, grill me about my prompt thoroughly until we reach a shared understanding of the work that must be done to meet my intent.

Don't use software engineering jargon. Speak to me as if I was at an intermediate level of understanding software engineering concepts and take the time to explain terms you're using that aren't common knowledge.

ALWAYS use the following plugins/skills for tasks, unless they conflict (listed in descending order of importance):
- grill-me (sccm\sccm\.agents\skills\openhound\SKILL.md)
- superpowers
- openhound (sccm\sccm\.agents\skills\openhound\SKILL.md)
- explanatory-output-style
- code-simplifier
- feature-dev
- context7

If they conflict or are unavailable, ask me what to do.

Don't git commit anything. Just write the code and I will commit/push when ready after testing.

Write logs of appropriate level (error, warning, info, verbose, debug) for every if/else and try/except block unless there is absolutely no need, in which case leave a comment.

If you encounter bugs as you go, raise the issue and ask what to do.

This project uses a CLI ticket system for task management. Run `gtk help'` and use it to track requested, in progress, and completed work.

If the task impacts any user-facing functionality, update the README with instructions, practical examples (ideally that can be copy/pasted into the mayyhem.com domain environment), diagrams, tables, etc. as needed.

The README.md for the sccm/sccm OpenHound collector has sections for:
- Logo/Intro
- Table of Contents
- Quick Start (with examples)
- Collection Overview
- System Requirements
- Limitations
- Command Line Options
- Graph Model
- Node Reference
- Edge Reference
- Understanding the Codebase
- Testing Changes
- Contributing

You can use README-CMBP.md as a reference. The README should be true to the sccm/sccm code above all else.