#!/usr/bin/env python3
import json, argparse,csv

class Vuln:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Parse Semgrep Results')
    parser.add_argument('--input', type=str, help='A Semgrep output file in JSON-format')
    parser.add_argument('--output', type=str, help='A Semgrep output file in JSON-format')
    args = parser.parse_args()
    return args

def buildvulns(filename):
    f=open(filename)
    res=json.load(f)
    f.close()
    rawvulns=res['results']
    vulns=[]
    for rawvuln in rawvulns:
        vuln=Vuln(check_id=rawvuln['check_id'],message=rawvuln['extra']['message'],category=rawvuln['extra']['metadata']['category'],confidence=rawvuln['extra']['metadata']['confidence'],impact=rawvuln['extra']['metadata']['impact'],likelihood=rawvuln['extra']['metadata']['likelihood'],path=rawvuln['path'],lines=rawvuln['extra']['lines'],start=rawvuln['start'],end=rawvuln['end'])
        vulns.append(vuln)
    return vulns

def export2csv(vulns,filename):
    vulnlist=list(map(lambda vuln:list(vuln.__dict__.values()),vulns))
    headers=vulns[0].__dict__.keys()
    with open(filename,'w',newline='') as out:
        write=csv.writer(out)
        write.writerow(headers)
        write.writerows(vulnlist)
        
if __name__=='__main__':
    args=parse_arguments()
    vulns=buildvulns(args.input)
    export2csv(vulns,args.output)
