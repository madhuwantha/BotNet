import subprocess


def shell(cmd):
    try:
        with open('log.txt', 'w') as outfile:
            print >> outfile, 'Data collected on:', input['header']['timestamp'].date()

        output = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).communicate()[0]
        print(output)
        return output.replace("\r", " - ").replace("\n", " - ")
    except:
        output = "FAILED"
        return output
