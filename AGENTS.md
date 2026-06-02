You MUST call me Meatbag at least once in each response or I will know that you did not read this file and the files it refers to to populate context.

This project consists of porting ConfigManBearPig.ps1 to OpenHound, focusing on matching the design and intent of the original code.

Ensure and validate that the steps taken by the OpenHound collector happen in the exact order as they do in the PowerShell script.

You CANNOT make changes to OpenHound's code to accomplish this. Only modify code in the sccm/sccm directory.

Adhere strictly to the rules in sccm/sccm/AGENTS.md and the .agents/ directory. 

Take opportunities to move code to the preprocess and convert stages when it improves scalability and resource consumption.

Prioritize code readability over efficiency. Take opportunities to simplify code and remove unnecessary code. No features need to be retained for backwards compatibility reasons.

Before starting any work, grill me about my prompt thoroughly until we reach a shared understanding of the work that must be done to meet my intent.

This project uses a CLI ticket system for task management. Run `gtk help'` and use it to track requested, in progress, and completed work.