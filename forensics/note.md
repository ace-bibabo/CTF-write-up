# What is Digital forensics

## Skills of Professional Parts

* technical proficient
* understand forensic process
* problem solving ability
* understand legal requirments
* strong ethics
* questioning mindset


> Digital evidence is said to be forensically sound if it was collected, analysed, handled and stored in a manner that is acceptable by the law, and there is reasonable evidence to prove so. Forensic soundness gives reasonable assurance that digital evidence was not corrupted or destroyed during investigative processes whether on purpose or by accident.

## Forensic Sound

* digital evidence has been collected via a standard, documented and proven forensic process
* for evidence to be admissible, needs to be defensible and repeatable
* the process includes seizure -> acquistion -> analysis -> reporting -> presentation

## Ethics
* honesty & competency: relecting on your own capabilities , make sure ur qualitified; continual development; presenting evidence in court honestly, accurately and compeletly
* understanding the legal boundaries: obtain evidence legally; understand standards of proof
* Objectivity: un-biased ; limit the scope
* independence: avoid a confict of interest 
* integrity: be transparent and disclose any potential conflicts of interest
* confidentially
* being a good human


# Investigative process

> where the computer lab meets art

##  case study-intellectual property theft

* basic: timezone/os version/topology of drive and drive volumnes
* email analysis
* windows registry
	* Prefetch: Identifies when applications were run.(speeding up the loading of apps), located at C:\Windows\Prefetch\
	* UserAssist (**ROT13 & NTUSER.DAT hive**): Tracks the programs and applications accessed through the GUI.
	* ShellBags(**SOFTWARE hive**): Records folder access and view settings by windows explorer. even deleted
	* Link Files(**NTUSER.DAT hive**): shortcut files created to a target file or app, containing the info of target file path/creation time/last access time and other metadata.
	* USB Drive: MountedDevices & USBSTOR key in **System hive**

## reporting your findings-structure
### responsibilities of an expert witness
* understand and comply with their duty to assist the court
* refrain from acting as an advocate for a party
* Comply with the Court’s directions and adhere to the Practice Direction in the relevant jurisdiction
* Know what issues they are being asked to consider;
* Identify if they need further information or instruction in order to give their opinion;
* Confine their opinion and their evidence to the issues relevant to their area of expertise;
* Expose the facts, assumptions, methodology, and reasoning that supports their opinion;
* Fully engage in a meeting of experts, if required;
* Be prepared to change, qualify, or revise their opinion where necessary and where the evidence no longer supports their opinion;
* Changes to an opinion expressed in a report filed with the Court, explain what factors or information resulted in that change of opinion.

### legal instructions
* You will generally receive instructions from legal teams to direct your report
* Remember you are independent (this relates back to professionalism and ethics)
* The Legal team will ask questions pertinent to the matter which you will answer

### You are telling a story – so paint a picture and position your role
* The background of the matter
* What you were instructed to do
* Who you are and why you are qualified to be presenting this material
* The information you relied on
* Disclaimers/Assumptions
* What you are presenting
* Legal Obligations
* Your findings, conclusion and/or opinions

## case study - report
### Setting the scene
* Explaining how you were engaged
* Any key dates/times of events or correspondences
* Establishing chain of custody
* Forensic imaging process

### The Mobile Devices
* Do you remember what state you found the Mobile Devices in?
* What did we infer from that and how did it direct our investigation?
* Could you explain that process in court?
* How do you remain unbiased?
* What questions would you might get from opposing counsel?

### Making an Opinion
* the definition of an opinion as “an inference from observed and communicable data” as sufficient for its purpose.
* An opinion can be admissibly in other words an expert opinion. An expert opinion is one where the information it conveys is likely to be outside the experience and knowledge of a judge or jury
* Opinions based on the expert witness’s own interpretation of the evidence are [admissible], provided that the reasoning process is properly explained and is shown to depend on the expert’s specialised knowledge.
* We can’t say for certain, but we can make our opinion based on the fact that:
	* The mobile devices were wiped
	* A professional’s knowledge and experience
	* Presenting all possibilities (ie, present our reasoning process)

# Giving evidence
## framework for good digital forensic practice
* relevant(is it a fact/opinion): is it a right piece of puzzle
	* credibility of a witness
	* admissibility of other evidece
* reliable(evidence/witness): are they the right place
	* the witness
		* qualified
		* truthful and unbiased
		* compromised
	* the process
		* administrative process (lawfully acquired/chain of custody)
		* scientific process: predictable/repeatable/equipment calibrated and operating correctly
* sufficient(standard proof/prove the right things): are they enough pieces of puzzle
* persuasive(understood by the decision-makers/know the audience): can u persuade a decision-maker that your thesis is the right one

## witnesses

* a witness presents evidence proves or disproves a fact, it can be inculpatory or exculpatory, direct or circumstantial, admissible or inadmissible, direct or hearsay
* types 
	* lay witness (I saw/heard)
	* investigator: discover facts
	* expert: who has specialized knowledge to provide an opinion based on their expertise
	* independent expert

# the theatre of court

## sessions in giving oral evidence
* evidence in chief 
* cross examnination
* re-examination
## ur right to access stored data 
* principle: the person of entity thta legally owns the computer is the only person who can authorize access to the data stored on it, except if access the access is illegal
	* access to the computer and data **stored on** the computer
	* those legally entitled to act on the owner's behalf
	* different to authorizing access to **communications** (only the recipent)
	* different to data accessed from the computer (although a cache or sync copy is okie)