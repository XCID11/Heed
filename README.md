# Heed
Automate the process of triaging, processing, sigma and yara scanning

The tool has been created to automate the process of working with dead images of Windows for forensics investigation. 

Download all needed tools as described on the following article. 


Use the following command to run Heed. 
.\heed.ps1 -i "K:\drive\images" -e "artifacts_CVE_xxx" -s "E:\saved\path\"

# PARAMETER i
## The image location. e.g E:\Path\to\image\

# PARAMETER e
## The folder name that contains the artifacts. e.g. Artifacts

# PARAMETER s
##This parameters is required to specify where you want the artifacts to be stored. e.g. E:\Path\
