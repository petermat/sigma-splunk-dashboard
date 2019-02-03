#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''

SIGMA rule repository convertor to Splunk Dashboard

Usage:

    Review rules

        python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml --info

    Run script

        python create_splunk_dashboard.py -di sigma/rules/windows/sysmon --config splunk-windows-all.yml

'''

import os, sys, re
import glob
import subprocess, shlex
from subprocess import PIPE
import datetime
import yaml
from jinja2 import Template


def is_valid_file(parser, arg):
    """
    Check if arg is a valid file that already exists on the file system.

    Parameters
    ----------
    parser : argparse object
    arg : str

    Returns
    -------
    arg
    """
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


def get_converted_rules(rule_dir, out_dir, config_file=None):
    print("="*80)
    print("\nStart processing {} rule files in '{}' directory:\n".format(len([glob.iglob(rule_dir + '**/*.yml', recursive=True)]),rule_dir))
    print("="*80,'\n')

    output_list = []
    for rulefile in glob.iglob(rule_dir + '**/*.yml', recursive=True):
        with open(rulefile) as myfile:
            if config_file:
                args = shlex.split("sigma/tools/sigmac -t splunk -c {} {}".format(config_file,rulefile))
            else:
                args = shlex.split("sigma/tools/sigmac -t splunk {}".format(rulefile))

            converted_rule =  (subprocess.run(args,
                                 stdout=PIPE, stderr=PIPE,
                                 # shell=True
                                 ).stdout.decode('utf-8'))


            sigma_obj_all = yaml.load_all(myfile)
            stable_list = list(sigma_obj_all)
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
                        sigma_obj['rule'] = converted_rule.split('\n')[counter-1]
                        for k,v in sigma_obj.items():
                            print("k:",k,"\t\t","v:",v)
                            #print(sigma_obj.get('title'))
                            #print('Severity:',sigma_obj.get('level'))
                            #print(sigma_obj.get('description'))
                            #print(converted_rule)
                            #print(sigma_obj.items())
                        print("-"*45)
                        output_list.append(sigma_obj)
                    counter +=1
            else:
                for counter, sigma_obj in enumerate(stable_list):
                    sigma_obj['rule'] = converted_rule
                    for k,v in sigma_obj.items():
                        print("k:",k,"\t\t","v:",v)
                        #print(sigma_obj.get('title'))
                        #print('Severity:',sigma_obj.get('level'))
                        #print(sigma_obj.get('description'))
                        #print(converted_rule)
                        #print(sigma_obj.items())
                    print("-"*45)
                    output_list.append(sigma_obj)
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
                        default=os.path.join("sigma","rules","windows","sysmon"),
                        type=dir_path,
                        help="reads sigma signatures per directory",
                        metavar="DIR")

    parser.add_argument( "-do", "--directory_out",
    					dest="output_dir",
    					default=os.path.dirname(os.path.realpath(__file__)),
                        type=dir_path,
					    help='Directory where the output files should be saved.',
					    metavar='DIR')
    
    parser.add_argument("-c", "--config",
                        dest="config",
                        default=None,
                        type=lambda x: is_valid_file(parser, x),
                        help="read the config file",
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

    searchcase_list = get_converted_rules(args.sigma_rule_directory,args.output_dir,  args.config)

    with open('templates/base.tmpl') as file_:
        template = Template(file_.read())
    rendr = template.render(searchcase_list=searchcase_list, now=datetime.datetime.today())

    with open(os.path.join(args.output_dir,"dashboard_code.txt"), "w") as myfile:
        myfile.write(rendr)