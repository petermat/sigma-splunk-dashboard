#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''

SIGMA rule repository convertor to Splunk Dashboard

Usage:

    Review rules
         $ python create_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml --info

    Run script with all rules in folder
        $ python create_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml

    Run script withour blacklisted fieldnames
        $ python create_dashboard.py -di sigma/rules/windows/sysmon \
            --config splunk-windows-all.yml \
            --blacklist 'CallTrace, DestinationHostname,DestinationIp,DestinationIsIpv6,DestinationPort,\
            Details,GrantedAccess,ImageLoaded,Imphash,PipeName,ProcessCommandLine,SourceImage,StartModule,\
            TargetFilename,TargetImage,TargetObject,TargetProcessAddress'

'''

import os, sys, re
import glob
from pathlib import Path
import subprocess, shlex
from subprocess import PIPE
import datetime
import yaml
from jinja2 import Template


def is_valid_file(parser, arg):
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg

def dir_path(string):
    if os.path.isdir(string):
        return string
    else:
        print("Error in '{}}': Sigma directory not nalid. Dependency 'git clone sigma' missing?".format(string))
        #raise NotADirectoryError(string)


def get_list_yml_filepaths(dir_name):
    return [filename for filename in glob.iglob(dir_name + '**/*.yml', recursive=True)]

def escape_splunk_html_splunk_query(query):
    for match in re.finditer('".*?[^\\\\]"', query):
        query = query[:match.start() + 1] + escape_splunk_html(query[match.start() + 1:match.end() - 1]) + query[match.end() - 1:]
    return query

def escape_splunk_html(dirty_string):
    bad = {
        "&": "&amp;",
        "'": "&apos;",
        "<": "&lt;",
        ">": "&gt;",
        "$": "$$"
    }
    if dirty_string:
        for k,v in bad.items():
            dirty_string = str(dirty_string).replace(k, v)
    return dirty_string
        # return str(dirty_string).replace("&","&amp;").replace("'","&apos;").replace("<","&lt;").replace(">","&gt;")


def get_fieldnames_info(rule_dir, config_file=None):
    args = shlex.split("sigma/tools/sigmac -r -t fieldlist {}".format(rule_dir))
    fieldnames = (subprocess.run(args,
                                 stdout=PIPE, stderr=PIPE,
                                 # shell=True
                                 ).stdout.decode('utf-8')).split('\n')

    print("="*80)
    print("\n{} Field name found in '{}' directory:\n".format(len(fieldnames),rule_dir))
    print("="*80,'\n')
    for field_name in fieldnames:
        if field_name:
            print("Field name: {}".format(field_name))
            counter = 0
            for rulefile in glob.iglob(rule_dir + '**/*.yml', recursive=True):
                with open(rulefile) as myfile:
                    if field_name in myfile.read():
                        print('\t'+rulefile)
                        counter +=1
            print("\n\t> Found in {} rules\n".format(counter))
            if config_file:
                for line in open(config_file).readlines():
                    if field_name in line:
                        print('\t> Remapped: {}\n'.format(line))

def enhance_rule_table(rulestring):
    # define important field names to add to table
    interesting_fields = ['User','ComputerName','ParentCommandLine', 'CommandLine','ParentImage','Image','CurrentDirectory']
    notintersting_fields = ['Message','_raw']

    if len(rulestring.split("| table ")) > 1:
        rulestring = rulestring.split("| table ")[0] + '| dedup ' + ','.join(interesting_fields) + '| table ' + ','.join(interesting_fields)
    else:
        rulestring = rulestring + '| dedup ' + ','.join(interesting_fields) + '| table ' + ','.join(interesting_fields)
    return rulestring


def get_converted_rules(rule_dir, out_dir , prefix_list=[], blacklist=None, config_file=None):
    output_list = []
    printout_processed =[]
    printout_skipped = []

    rule_files = []
    if prefix_list:
        for prefix_str in prefix_list:
            rule_files += list(Path(os.path.join(rule_dir)).rglob("{}_*.yml".format(prefix_str)))
    else:
        rule_files += list(Path(os.path.join(rule_dir)).rglob("*.yml"))



    regexban = re.compile('.*deprecated.*')  # remove nonrelevant
    filtered = [str(i) for i in rule_files if not regexban.match(str(i))]

    print("="*80)
    print("\nStart processing {} rule files in directory: {}".format(len(filtered), rule_dir))
    if prefix_list: print("! Including only fies with these prefixes: {}".format(', '.join(prefix_list)))
    print("="*80, '\n')

    #for rulefile in glob.iglob(rule_dir + '**/*.yml', recursive=True):
    for counter, rulefile in enumerate(filtered):
        #if blacklist:
        #    args = shlex.split("python create_dashboard.py --config {} --info {}".format(config_file, rulefile))

        with open(rulefile) as myfile:
            if config_file:
                if not isinstance(config_file, list):
                    config_file = [config_file,]
                args = shlex.split("sigma/tools/sigmac -t splunk {} {}".format(''.join([' -c '+x for x in config_file]),
                                                                                  rulefile))
            else:
                args = shlex.split("sigma/tools/sigmac -t splunk {}".format(rulefile))

            converter = subprocess.run(args, stdout=PIPE, stderr=PIPE)
            print("-" * 80)
            if converter.returncode != 0 and not converter.stdout:

                print("Unable to convert rule file:", rulefile)
                print("output:")
                print(converter.stderr.decode('utf-8').strip())
                print("-"*80)
                print()
                printout_skipped.append(f"{rulefile} because sigmac was unable to convert the file, error code {converter.returncode}")
                continue
            else:
                print("File {}/{} loaded: {}".format(counter+1,len(rule_files),rulefile))

            converted_rule = converter.stdout.decode('utf-8').strip()
            converted_rule = escape_splunk_html_splunk_query(converted_rule)

            if blacklist:
                matched_blackwords = []
                for black_word in blacklist:
                    if " "+black_word+"=" in converted_rule:
                        matched_blackwords.append(black_word)

                if matched_blackwords:
                    print("SKIP rule {} matched these blacklisted field names: {}".format(rulefile,matched_blackwords ))
                    printout_skipped.append("{} because contains {}".format(rulefile,matched_blackwords))
                    continue

            sigma_obj_all = yaml.load_all(myfile, Loader=yaml.FullLoader)
            stable_list = list(sigma_obj_all)

            # For cases when there are multiple UCs in one files
            if len(stable_list) > 1:
                counter=0
                for sigma_obj in stable_list:

                    if sigma_obj.get('title'):
                        sigma_obj_parent = sigma_obj
                    else:

                        for k,v in sigma_obj_parent.items():
                            if k not in sigma_obj:
                                sigma_obj[k] = v
                                if k == 'title':
                                    sigma_obj[k] = v + " " + str(counter)
                            else:
                                sigma_obj[k].update(v)

                    if counter >0:
                        sigma_obj['pure_rule'] = converted_rule.split('\n')[counter-1]
                        sigma_obj['rule'] = enhance_rule_table(sigma_obj['pure_rule'])
                        sigma_obj['title'] = escape_splunk_html(sigma_obj.get('title'))
                        sigma_obj['description_esc'] = escape_splunk_html(sigma_obj.get('description'))
                        sigma_obj['references_esc'] = escape_splunk_html(sigma_obj.get('references'))
                        sigma_obj['detection_esc'] = escape_splunk_html(sigma_obj.get('detection'))
                        """ # debug printout
                        for k,v in sigma_obj.items():
                            print("k:",k,"\t\t","v:",v)
                            #print(sigma_obj.get('title'))
                            #print('Severity:',sigma_obj.get('level'))
                            #print(sigma_obj.get('description'))
                            #print(converted_rule)
                            #print(sigma_obj.items())
                        print("-"*45)
                        """
                        output_list.append(sigma_obj)
                        printout_processed.append(sigma_obj['title'])
                    counter +=1

            # Only one rule per file
            else:
                for counter, sigma_obj in enumerate(stable_list):
                    sigma_obj['pure_rule'] = converted_rule
                    sigma_obj['rule'] = enhance_rule_table(sigma_obj['pure_rule'])
                    sigma_obj['title'] = escape_splunk_html(sigma_obj.get('title'))
                    sigma_obj['description_esc'] = escape_splunk_html(sigma_obj.get('description'))
                    sigma_obj['references_esc'] = escape_splunk_html(sigma_obj.get('references'))
                    sigma_obj['detection_esc'] = escape_splunk_html(sigma_obj.get('detection'))
                    """ # debug printout
                    for k,v in sigma_obj.items():
                        print("k:",k,"\t\t","v:",v)
                        #print(sigma_obj.get('title'))
                        #print('Severity:',sigma_obj.get('level'))
                        #print(sigma_obj.get('description'))
                        #print(converted_rule)
                        #print(sigma_obj.items())
                    print("-"*45)
                    """
                    output_list.append(sigma_obj)
                    printout_processed.append(sigma_obj['title'])

    #print summary
    print("\n","="*60)
    print("Skipped rules ({}):".format(len(printout_skipped)))
    for skipped_r in printout_skipped:
        print("\t"+skipped_r)
    print("\n", "-"*60)
    print("Processed rules ({}):".format(len(printout_processed)))
    for processed_r in printout_processed:
        print("\t"+processed_r)
    return output_list


def get_parser():
    """Get parser object for script xy.py."""
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    #parser.add_argument("-f", "--file",
    #                    dest="filename",
    #                    type=lambda x: is_valid_file(parser, x),
    #                    help="write report to FILE",
    #                    metavar="FILE")
    
    parser.add_argument("-di", "--directory_in",
                        dest="sigma_rule_directory",
                        default=os.path.join("sigma", "rules", "windows"),
                        type=dir_path,
                        help="reads sigma signatures per directory",
                        metavar="DIR")

    parser.add_argument( "-do", "--directory_out",
                        dest="output_dir",
                        default=os.path.dirname(os.path.realpath(__file__)),
                        type=dir_path,
                        help='Directory where the output files should be saved.',
                        metavar='DIR')

    parser.add_argument( "-pf", "--prefix_list",
                        dest="prefix_list",
                        nargs='+',
                        default=[],
                        help='List of file rule prefixes to process')

    parser.add_argument("-c", "--config",
                        dest="config",
                        default=None,
                        type=lambda x: is_valid_file(parser, x),
                        help="read the config file",
                        metavar="FILE")

    parser.add_argument("-b", "--denylist",
                        dest="denylist",
                        default=None,
                        type=str,
                        help="list of rule names to denylist",
                        metavar="FILE")

    parser.add_argument("-i", "--info",
                        action="store_true",
                        dest="info",
                        default=False,
                        help="print info for loaded rules")

    parser.add_argument("-q", "--quiet",
                        action="store_false",
                        dest="verbose",
                        default=True,
                        help="don't print status messages to stdout")
    return parser


if __name__ == "__main__":
    args = get_parser().parse_args()

    if args.info:
        get_fieldnames_info(args.sigma_rule_directory, args.config)

    else:
        black_list = None
        if args.denylist:
            deny_list = [str(item.strip()) for item in args.denylist.split(',')]


        searchcase_list = get_converted_rules(args.sigma_rule_directory,args.output_dir, args.prefix_list, black_list, args.config)

        with open('templates/base.tmpl') as file_:
            template = Template(file_.read())
        rendr = template.render(searchcase_list=searchcase_list, now=datetime.datetime.today())

        with open(os.path.join(args.output_dir,"dashboard_code.txt"), "w") as myfile:
            myfile.write(rendr)


