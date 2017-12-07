import socket
import os
import sys
import csv
import os.path
import glob
from PLcrypto import *
from aes import *
import no_bytecode
from ClearScreen import *

def read_pass(client, key, clientkey, aeskey):
  client.send(PLencrypt("Entries: ", key, aeskey))
  contents = ""
  dir_contents = os.listdir('.')
  if dir_contents:
    for file in glob.glob("*.csv"):
      file = file[:-4]
      print(file)
    client.send(PLencrypt("Enter the name of the entry you would like to read: ", key, aeskey))
    entry = PLdecrypt(client.recv(1024), clientkey, aeskey)
    if not entry:
      client.shutdown(socket.SHUT_RDWR)
      client.close()
      sys.exit(1)

    with open("%s.csv" % entry, "r") as f:
      reader = csv.reader(f)
      for row in reader:
        contents = "username: "+aesdecrypt(row[0], enckey('../'))+"\npassword: "+aesdecrypt(row[1], enckey('../'))+"\n"

    return contents
  else:
    clearscrn()
    return "There are no saved passwords\n"
