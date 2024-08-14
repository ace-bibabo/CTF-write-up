## Physical Evidence Handling

### preparation-The Lab

* hardware
	* forensic workstation, powerful machines, forensic software
	* secure evidence holding, physical evidence safe, tamperproof seals and bags, forms
	* writeblockers and adaptors
* software
	* imaging software: Encase, FTK, Paladin
	* analysis software: Encase, FTK, SIFT, log2timeline, Internet evidence finder
	* supporting software: screenshoting software, robocopy
* people

### seizure

* covert vs overt
* legal
* secure the scene
	* before pulling the power, make sure taking a live image
	* some devices cant pull the power, the only option force shut down and if non-removable drive, so a USB/CD boot acquisition is required
	* the risk of remote wipe tools, put them into airplane mode to disable all radios or use a faraday bag
* ABD
	* work journals: note key steps in the process, and capture acquisition information
	* chain of custody forms
	* imaging forms: device model, serial number
	* physical evidence check-in check-out: start, stop times of the acquisition, and the acquisition hash
	* forensic report
* maintain chain of custody

### forensic acquisition
>create an exact forensic copy of digital evidence

* disk acquisition: remove the drive from the device, and attach it to a forensic workstation, or specialized forensic duplicator
* live acquisiton: Run the forensic software directly on the deveces OS, and store on an external drive
* BOOT CD/USB acquisition: Boot the device from a CD or USB loaded with an OS containing forensic tools, and store on an external drive
* Network acquisition: connect directly to a device over the network, and acquire using an agent either pre-installed, or deployed demand
* a write blocking provides a physical barrier to any write requests to the disk

### forensic image formats

#### expert witness format

* Pros:
	* Hash calculation and case metadata is baked into the format. (Impossible to create an E01 that
	* does not have hashes baked in)
	* Redundant integrity checks, Block and Device level hashing.
	* Can be split into segments for ease of handling.
	* Native support for compression.
* Cons:
	* Harder to make native commands work with E01 files. (though not impossible – libewf)
	* Need specialised software or libraries to create an E01.

## Disk structure and acquisition approaches

### drive physical structure
* traditional drives: a number of platters, each containing a number of tracks, each contains a number of **blocks/sectors which are base unit **is addressable on the disk
* Solid state drives: use NAND Flash memory chips

### drive logical structure

#### MBR
* master boot record, contains the volume locations and sizes
* first sector on the drive which contains the bootstrap code
* the next 64 bytes contain a partition table (each partition entry describes the info of the start sector, size, and partition type) which a max of 4 entries but can use a extended volumes but hard to manage
* a use of 32bit sector addresses which limit to a 2TB storage

#### Partitions
* a contiguous block on a physical disk which is the **a low-level division of the disk**.
* unpartitioned space: raw disk editor/ os apis/ driver level apis
* hidden partitions: VeraCrypt Hidden Volume

####  Volumes
* Logical containers for filesystems. Note that while the Filesystem and Volume are often referred to as the same thing, they are technically separate. (You can have an empty volume!)
* slack: unused space between the end of the file system and end of partition where the file system resides or cannot be allocated to a cluster.

#### Filesystems
* Structures that sit within a volume, and allow files to be organised and saved.

#### Clusters
* Sectors are not an efficient way for file systems to address data blocks. Therefore, they are organised into **clusters**. The cluster size is how many sectors are grouped into a single cluster. Files are assigned entire clusters as they grow.

#### Unpartitioned Space 
* If you don’t assign all sectors to a partition, they will sit within unpartitioned space on the drive.

## Acquisition - Physical vs Logical vs LEF

### Physical Image /.//PhysicalDrive1 /dev/sda

* image an entire physical device, including all partitions, collects everything available
* capture all areas of disk, including unpartitioned space, volume slack
* supported by expert witness format

### Logical Image C:\ /dev/sda0
* image only a selected partition
* will capture some slack areas, but not unpartitioned space
* supported by expert witness format

### LEF-Logical Evidence file C:\Users\Public\Documents /Users/joeblogs/Documents
* image a collection of files, or folders
* doesn't capture slack space at all
* requires another format (L01, AD1)

### RAID - Redundant Array of Inexpensive Disks
* multiple hard disks as a single logical volume of storage for the OS to utilize
* rely on some logic to translate the logic disk structure to physical disk
* can be hardware driven like a raid controller or software driven like MS Storage spaces
* challenges
	* all disks need to be captured
	* dramastically increases imaging time
	* ordering of the disks
	* reconstructing the RAID after imaging

### Cloud Based Disks
* optionA : acquire a copy of VM 
* optionB : acquire live on the cloud system


## Filesystems and Timelining

> filesystems are the way in which OS manage files and folder structures on the disk

### NTFS
* default windows system since Windows NT 3.1, as a replacement of FAT (file allocation table)
* **sparse file support**: Support for sparse files (files that can consume less disk space by only using storage for non-empty portions) and reparse points (used for advanced features like symbolic links).
* **disk use quotas**: Administrators can set disk quotas, which limit the amount of disk space that users can consume, helping to manage and allocate storage resources efficiently.
* **reparse point**: enables advanced file system functionalities, such as symbolic links, junction points, and volume mount points.
* **EFS**: file-level encrytion, which enables users to protect sensitive data by encrypting files and folders 

### NTFS VBR (Volume Boot Record)
* first sector of an NTFS partition, typically sector0 which is 512 bytes
* **jump instruction**: A small piece of code that tells the system where to find the rest of the boot code within the sector.
* **OEM ID "NTFS"**: (Original Equipment Manufacturer ID) is a unique identifier used in the file system's boot sector to specify the type of file system which helps the operating system and other software recognize the file system type and load the appropriate drivers or routines.
* **Filesystem geometry**: refers to the layout and organization of the file system on the disk, including details such as the size of clusters, sectors, and the arrangement of file system structures.
* **Cluster that contains the $MFT**: 
	* be considered as dir for the filesystems
	* master file table contains metadata about all files and directories on the volume, including their names, attributes, and locations.
	* **MFT entry bitmap**: an attr that keeps track of which MFT File are in-use, and which are free for reuse.
	* **resident data**: a file is small that stored at MFT directly, and when it grows will become non-resident, the original maybe partially overwritten but not zeroed out, and it never become resident agagin. so it's a good place to recover deleted data in terms of a digital foresics view
	* **$Data attr & Cluster Runs**: Header (no. of the bytes used of the length and offset) Length(no. of the contiguous clusters ) Offset (starting point of the cluster run)
	* **Alternate Data Streams (ADS)**: which is a functionality to store multiple data streams which enables the storage of supplementary metadata, such as echo "super secret" > normal.txt:secret.txt, and using 'dir/r' can list all data streams.
	* **Deleted Files**: 
		1. 	MFT marks the File entry as re-useble
		2. $Data attr of the file is read and $BITMAP updated to show that cluster run are no longer in use
		3. until the File entry is overwritten, the full location of the data is stored in the $DATA attr cluster runs
		4. data itself still in the data clusters until are re-allocated by the system to a new file
	* **Drive Slack**: file are allocated to files at a cluster level if a file doesn't fill the entire cluster, the remaining slack may contain residual or hidden data
	* **File/RAM Slack**: data can only be allocated in sectors, but if is smaller than a sector, Windows will padding with zeros
	* **unallocated clusters**: refers to the collection of clusters that are not assgined to any file and related to the 'File carving' by looking for file signatures
* **cluster that contains the backup MFT $MFTMirr**: reserved area on the disk where a mirror copy of the $MFT is stored

### CMDs
* img_stat: basic info about image
* mmls: decode the partition table
* fsstat: show partition details
* istat: show FAT/MFT entry for a particular file
* icat: show data for a file
* etc


### FAT32
* Volume Boot Record
* File Allocation Table: directory entries only store the beginning cluster of a file, a big linked list, with each value pointing to the next cluster user by the file
* Directory Entries
* Deleted files
	1. 	the fist character of the filename attr is modified to 0xe5(_ or !)
	2. all cluster runs in the FAT are zeroed out, so we wont be able to follow them to restore data

### Linux and Mac Filesystems
* linux: ext* family
* mac: HFS, APFA

## Registry
> is a hierarchical database which stores low-level settings fro MS windows OS

* SAM – Security Accounts Manager, contains user and group membership info. located at C:\Windows\System32\config\SAM
* SYSTEM – contains information about the Windows system setup, the list of currently mounted devices containing a filesystem, configurations for system hardware drivers and services running on the local system. C:\Windows\System32\config\SYSTEM
* SOFTWARE - contains software and Windows settings. It is mostly modified by application and system installers C:\Windows\System32\config\SOFTWARE
* SECURITY - The kernel will access it to read and enforce the security policy applicable to the current user and all applications or operations executed by this user. C:\Windows\System32\config\SECURITY
* There is also a per user hive • NTUSER.dat C:\Users\<userprofile>\NTUSER.dat

### registry analysis

#### confirming the envr
* OS version: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
* Timezone: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion, BIOS Time
* Computername : 
HKLM\SYSTEM\ControlSet###\Control\ComputerName\Compu terName HKLM\SYSTEM\ControlSet###\Services\Tcpip\Parameters
* User Accnt: HKLM\SAM\Domains\Account\Users\

#### evidence of usb usage
* The Plug & Play Log Files: XP - C:\Windows\setupapi.log; Win7 - C:\Windows\inf\setupapi.dev.log
> we can now say the new plug and play deveies in what time
* USBSTOR: SYSTEM\ControlSet###\Enum\USBSTOR
> what usb devices have been pluged in by checking USB ClassGUID/ manufacturer name / serial num
* MoutedDevices: SYSTEM\ControlSet###\Enum\USBSTOR
> we can now say USB devices were last assgined to each drive letter
* MountPoints2: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersio n\Explorer\MountPoints2
> we can now say what user accnt wa logged in which drive was attached

#### Linkfiles
> "shortnut" files used by windows for features such as "Recents", this frequetly get creted when a file is opened from windows explorer
* including original path and filename of file, including driver letter or network path
* the timestamops of the target file (in addition to its own timestamps)
* for external drives, the volume serial number of the drive.
* useful for looking at usb history what file may have been on the device

#### Prefetch
> introduced in winXP which designed to speed uop the app startup process, and located at C:\Windows\Prefetch

* name of the executable
* unicode list of dlls used by the executable
* count of times for the executable has been run
* last time the app was run

#### UserAsst
> (ROT13) keep track of programs that executed which located at NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count, and only contains data on the apps launched by the user via windows Explorer which means programs launched via the cmd do not appear

* no. executions
* last exe date & time

## Memory Forensic

### what's in memory
>once the machine is powered down, its gone, and its not possible to acquire mem without midifying it

* fragment of non-valatile data (MFT, files, registry, event logs)
* drivers, daemons, system code
* recently executed terminal
* pwd, keys, security info
* running processes
* network conn
* clear text fragments

### Hibernation - other sources of mem
* Hibernation: when a computer enters hiberation state, it will dump a copy of physical mem to disk which created a file named 'hiberfil.sys' and is not deleted after the machine restores to running state

### Pagefile
* swapfile which on the disk laocation that holds mem that has been paged out of physical mem, and is now being stored on disk
* not a full dump
* a colloection of all 'gaps' in physical mem, using strings to extract any plain text fragments will still return useful info or use file carving tools (scalpel) to recover files based on a file signature

### Vmem
>many virtualisation tech provides a mechnism by which a copy of mem can be obtained without needing to run a program on the host itself

* when a VMware machine is suspended, raw mem is written to disk in a .vmem file

### Memory Acquisition Tools

* FTK Imager
* Redline collector
* dd/windd
* powershell

### Analysis Approach

* processes
	1. look for processes that are misspelling of proper system processed
	2. look for which have proper system names but spawned from the wrong file location
	3. look for duplicate processed for which there should only be one instance
	4. look at the user accnt
	5. malware authors may attempt to hijcak existing processes rather than start their own
	6. malwares will sometimes side load/inject dlls into an existing process
	7. a process holding onto out of the ordinary registry keys or files may indicate its running malware
	8. malware authors can attempt to create new threads within an already running process
	9. looking for suspicious mem objs
	10. frequency of least occurrence
	11. suspicious network activity: connect to some external system or receive new input from a remote attacker
* handles and dlls
* ports and network
* signs of code injection
* signs of rootkits
* export for further analysis

## Network Forensics
### barriers to network forensics
* encryption
* size of data + retentionre
* where capture was performed
* wireshark


## Mobile Device Forensics

### preparing for seizure
* mobile devices have multiple wireless radios and physical isolation is not be sufficient risk of remote wipe
* many phones can be difficult to completely power down
* encrytion 
* industry tools
	* XRY
	* Cellebrite

	
## incident response

### aims to
* find root cause
* scope out the impact
* remediate any issues and recover

### incident types
* data breach
* host/cloud compromise
* supply chain attack
* nuisance campaigns (DDoS, spam, phishing)
* product abuse

### steps
* Prepare
* Respond - OODA
	* observe
	* orient
	* decide
	* act 
* Refine