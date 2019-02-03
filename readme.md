# SIGMA Rules Splunk Dashboard #
Generate Splunk search app from SIGMA rules repository wrapping sigmac converter


# Requirements #

- clone/download this repository
    
    `git clone xxx`
    
    `cd xxx`

- clone Sigma repository [SIGMA rules](https://github.com/Neo23x0/sigma)

    `git clone https://github.com/Neo23x0/sigma.git`

- Setup VirtualENV

    `virtualenv -p python3 venv`
    
    `source venv/bin/activate`    



- install dependencies from requirements.txt

    `pip install -f requirements.txt`

Folder structure:

``` 
\templates
\sigma (clonned repo)
\create_splunk_dashboard.py
```


## Adjust config for target environment

1. Read [config manual](https://github.com/Neo23x0/sigma/wiki/Converter-Tool-Sigmac)

1. List fields from rules

    `python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml --info`

1. Edit config file 

    `nano splunk-windows-all.yml`


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


Example

    `python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml`



