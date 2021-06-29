# SIGMA Rules Splunk Dashboard #
Generate Splunk search app from SIGMA rules repository wrapping sigmac converter

Features:
- Allows easy update - New dashboards generated generated on SIGMA repo update 
- Use Jinga2 templating engine to generate template source code 
- Create Field name statistics for easier configuration
- All arguments parametrized

# Requirements #

1. Run the following commands to download the repository
```bash
git clone git@github.com:petermat/sigma-splunk-dashboard.git`
cd sigma-splunk-dashboard
```

Now simply run `sh gen-all.sh` to automatically setup the sigma repo, venv and start generating all the dashboards under `./dashboards/`. Alternativly follow the manual instructions.

## Manual install instructions
1. First setup the python virtual environment and install the python dependencies:
```bash
python -m venv venv
source venv/bin/activate
python install -r requirements.txt
```

2. Clone the Sigma repository [SIGMA rules](https://github.com/Neo23x0/sigma)
```bash
git clone https://github.com/Neo23x0/sigma.git
```

3. To manually start generating dashboard rules, run the following example command:
```bash
python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml 
```
This will use the config `./splunk-windows-all.yml` to generate splunk rules and will look for all `.yml` recursivly under the `sigma/rules/windows/sysmon` folder.

# Folder structure:

```bash
./templates    # templates used to generate the dashboard xml files 
./sigma        # cloned rules repository
./dashboards   # dashboards created by gen-all.sh
```


## Adjust config for target environment

1. Read [config manual](https://github.com/Neo23x0/sigma/wiki/Converter-Tool-Sigmac)
2. List fields from rules
```bash
python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml --info
```
3. Edit config file 
```bash
nano splunk-windows-all.yml
```


## Generate Dashboard

Help

```
python create_splunk_dashboard.py --help
usage: create_splunk_dashboard.py [-h] [-di DIR] [-do DIR] [-c FILE] [-i] [-q]

SIGMA rule repository convertor to Splunk Dashboard Usage: Review rules python
create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-
windows-all.yml --info Run script python create_splunk_dashboard.py -di
sigma/rules/windows/sysmon --config splunk-windows-all.yml

optional arguments:
  -h, --help            show this help message and exit
  -di DIR, --directory_in DIR
                        reads sigma signatures per directory (default:
                        sigma/rules/windows/sysmon)
  -do DIR, --directory_out DIR
                        Directory where the output files should be saved.
                        (default: /home/peter/workspace/sigma)
  -c FILE, --config FILE
                        read the config file (default: None)
  -i, --info            print info for loaded rules (default: False)
  -q, --quiet           don't print status messages to stdout (default: True)
```

