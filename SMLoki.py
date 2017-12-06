import sys, os
import re
import stat
import yara
import traceback

def get_dir_file(dirpath):
    """
        check dirpath here or ?
    """
    dir_file = []
    if os.path.exists(dirpath) and os.path.isdir(dirpath):
        for p, d, f in os.walk(dirpath, followlinks=False):
            for file in f:
                if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                    # In Fact, It's already filter by lib
                    continue
                dir_file.append(os.path.join(p, file))
        return dir_file


class SMLoki():
    """
        Customsized from https://github.com/Neo23x0/Loki  
        Loki Is A Simple IOC Scaner by use Yara , It's Very Useful
    """
    
    def __init__(self, rules=None, iocs=None):
        
        if rules == None and iocs == None:
            print("You Must Seeting A Rules Or Iocs Path ")
            sys.exit(1)
        
        self.rules = rules
        self.iocs = iocs
        self.yara_rules = []

    def output_res(self,res):
        if res:
            return True, res
        else:
            return False, None

    def init_yara_rules(self):
        if os.path.exists(self.rules):
            if os.path.isdir(self.rules):
                return self.compile_rules()
            elif os.path.isfile(self.rules):
                return self.load_rules()
        else:
            print("Yo, This rules can't be used, Now I will exit .\n")
            sys.exit(1)

    def compile_rules(self):
        """
        We will load the all rules in some special dir, ignore single one
        """
        yaraRules = ""
        dummy = ""

        for yaraRuleFile in get_dir_file(self.rules):
            try:
                extension = os.path.splitext(yaraRuleFile)[1].lower()

                try:
                    compiledRules = yara.compile(yaraRuleFile, externals={
                        'filename': dummy,
                        'filepath': dummy,
                        'extension': dummy,
                        'filetype': dummy,
                        'md5': dummy
                    })
                except Exception as e:
                    traceback.print_exc()
                    # if logger.debug:
                    #     sys.exit(1)
                    continue

                if extension == ".yar" or extension == ".yara":
                    with open(yaraRuleFile,'r') as rulefile:
                        data = rulefile.read()
                        yaraRules += data


            except Exception as e:
                traceback.print_exc()
                # if logger.debug:
                #     sys.exit(1)
                continue
    # Feel like it's not comfortable, why not compiled it directly?
    #Compile
        try:
            compiledRules = yara.compile(source=yaraRules,externals={
            'filename': dummy,
            'filepath': dummy,
            'extension': dummy,
            'filetype': dummy,
            'md5': dummy   
            })

        except Exception as e:
            pass

        return self.yara_rules.append(compiledRules)

    def load_rules(self):
        """
            Load Compiled Yara Rules, Exclude Dir
        """
        try:
            return self.yara_rules.append(yara.compile(self.rules))
        except yara.SyntaxError as e:
            # That's Mean you load a comlied yara rules, so now we try load
            try:
                return self.yara_rules.append(yara.load(self.rules))
            except:
                # import traceback
                # print(traceback.print_exc())
                print("Rules Was Wrong, Please Check it")

    def load_hash_iocs(self):
        pass

    def load_ip_iocs(self):
        pass

    def load_ip_iocs():
        pass        

    # def load_misp_ip_iocs():
    #     pass
        
    def scan_Target(self, Target):
        """
            Target may be:
                1. single file
                2. dir and file 
        """
        try:
            for rules in self.yara_rules:
                if os.path.isfile(Target):
                    res = rules.match(filepath=Target)
                    return self.output_res(res)
                elif os.path.isdir(Target):
                    res = []
                    for target in get_dir_file(Target):
                        tmp = {
                            'filename': target,
                            'filetype': rules.match(filepath=target) #, timeout = 60)
                        }
                        res.append(tmp)
                    return True, res

        except Exception as e:
            # It's not file, In Pastebin hunter, we can assign it as a simple string
            print ('---------------------------------------------------')
            return self.scan_string(Target)
    
    def scan_string(self,UnknownStrings):
        """
            Something Wrong,Can't hit it with the useful result
        """
        for rules in self.yara_rules:
            res = rules.match(data=UnknownStrings)
            return self.output_res(res)

def main():
    rulespath = os.path.abspath('./YaraRules/')
    # mydata = SMLoki(rules='/home/mour/working/apt-detector/tests/php_linux_3.7.0.yar')
    mydata = SMLoki(rules=rulespath)
    mydata.init_yara_rules()
    with open('/home/mour/resoures/webshell/php/wso/wso-4.2.0.php') as f:
        dbconnectionString = f.read()

    res = mydata.scan_Target(str(dbconnectionString))
    # res = mydata.scan_Target('/home/mour/resoures/webshell/php/wso/wso-4.2.0.php')
    print(res)
    
if __name__ == '__main__':
    main()
