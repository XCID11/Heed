# Heed | Automate the boring stuff

The tool has been created to automate the process of working with Windows images acquired from Windows machines for forensic investigations. Heed can help you focus on what is important and save time during the forensic process. This was the motivation behind creating this tool. Heed relies on other free/open-source tools, such as:

  * Arsenal Mount Imager: Help you to mount images
  
  * KAPE: To triage Windows images and processing them
  
  * ZircoLite: To scan Windows event logs with SIGMA rules
  
  * LOKI: To scan the Windows image for any known malicious file
  
  * Volatility3: Extract artifacts from Memory (if existed)
  

# Running Heed
You need the previous mentioned tools to run Heed and it has to be placed inside the same folder.

	Heed Folder >
		>heed.ps1
		>Arsenal Mount Imager - Has to run once through its GUI to install the necssary drivers to work.	
		>KAPE
		>ZircoLite	
		>LOKI	
		>Volatility3 - Make sure the tool is running and all depncises are installed

After having everything in place, run Heed through PowerShell with administrative privileges. 
Use the following command to run Heed. 

To check if other dependencies existed or not, run: 	
```Powershell
.\heed.ps1 -chk
```

If the previous commands sucessed, then you are ready to run Heed using this command:	

``` Powershell
.\heed.ps1 -i "K:\drive\images" -c "Case01" -s "E:\path\"

-i: image(s) path. e.g E:\Path\to\image\

-c: for Case name	

-s: Saving location
```

To have a prettier terminal and suppress the output of KAPE, Zircolite then use this flag `-nd`. 

```Powershell
.\heed.ps1 -nd -i "K:\drive\images" -c "Case01" -s "E:\path\"
```

