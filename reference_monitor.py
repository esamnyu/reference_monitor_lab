
"""
This security layer inadequately handles A/B storage for files in RepyV2.



Note:
    This security layer uses encasementlib.r2py, restrictions.default, repy.py and Python
    Also you need to give it an application to run.
    python repy.py restrictions.default encasementlib.r2py [security_layer].r2py [attack_program].r2py 
    
    """ 
TYPE="type"
ARGS="args"
RETURN="return"
EXCP="exceptions"
TARGET="target"
FUNC="func"
OBJC="objc"

mycontext['lock'] = secure_createlock()

class ABFile():
  def __init__(self,filename,create):
    # globals
    mycontext['debug'] = False   
    # local (per object) reference to the underlying file
    self.Afn = filename+'.a'
    self.Bfn = filename+'.b'
    
    # make the files and add 'SE' to the readat file...
    if create:
      # If create is true, check for an existing Afile and Bfile  
      if self.Afn in listfiles():
        #If the file exists, open the files and replace the contents of Bfile with Afile
        self.Afile = openfile(self.Afn,create)
        self.Bfile = openfile(self.Bfn,create)
        self.Bfile.writeat(self.Afile.readat(None,0),0)
      else:
        # If the files do not exist, then create the files and append 'SE' to them
        self.Afile = openfile(self.Afn,create)
        self.Bfile = openfile(self.Bfn,create)
        self.Afile.writeat('SE', 0)
    else:
      #if create is False
      if self.Afn in listfiles():
        #Then the file exists
        self.Afile = openfile(self.Afn,True)
        self.Bfile = openfile(self.Bfn,True)
        self.Bfile.writeat(self.Afile.readat(None,0),0)
      else:
        #Does not exist and False
        raise FileNotFoundError


  def writeat(self,data,offset):
    # Write the requested data to the B file using the sandbox's writeat call
    # if len(self.Bfile.readat(None, 0)) < len(data):
    # 	return None
    # if len(self.Bfile.readat(None, 0)) < offset:
    #   return None
    # if len(data) <= len(self.Bfile.readat(None, 0)):
    #   self.Bfile.writeat(data, offset)
    #Write File
    #Creating and acquiring a lock prevents other threads from performing concurrent operations to the Bfile in this case, 
    #Having concurrent operations occur means that a two or more threads attempt to access a single resource, creating a race condition, causing unpredictable results 
    mycontext['lock'] = acquire(True)
    # Write the requested data to the B file using the sandbox's writeat call
    if offset < 0 or len(data) < 0:
      # Instead of returning none, raise an argument error, offset cannot be negative 
    
      # raise RepyArgumentError
      return None
    # If the current offset is greater than the length of the data in the Bfile
    elif offset > len(self.Bfile.readat(None,0)):
      #Identified the proper error, instead of returning None
    #   self.lock.release()
      return None 
    elif (offset + len(self.Bfile.readat(None, 0)) > len(self.Bfile.readat(None, 0))) and data != None:
      self.Bfile.length = offset + len(self.Bfile.readat(None, 0))
      self.Bfile.writeat(data,offset)
      #self.lock.release()
    else:
      self.Bfile.writeat(data,offset)
      #Below line is highlighted, meaning that it is reached in code
      #self.lock.release()

  # Do not raise errors 
  def readat(self,bytes,offset):
    #Read File
    # Read from the A file using the sandbox's readat...
    #Create the lock 
    # self.lock = createlock()
    #When the lock is acquired, by nature it blocks another thread from trying to access the resource in question 
    # self.lock.acquire(True)
    #Read the length of data in the Afile
    length = len(self.Afile.readat(None,0))
    #Offset cannot be negative, and the length of the data in Afile cannot be negative
    if length < 0 or offset < 0:
      #Raise an argument error otherwise
      # raise RepyArgumentError
      # mygloballock['lock'] = release()
      return None
      # The passed offset is itself greater 
    elif offset >= len(self.Afile.readat(None,0)):
      # raise SeekPastEndOfFileError
      # mygloballock['lock'] = release()
      return None
    elif bytes != None and bytes > length:
      # mygloballock['lock'] = release()
      # raise SeekPastEndOfFileError
      return None
    # the length of the data in Afile plus its offset is greater than Afile size: this already would raise an error, if the bytes (aka data is nonzero)
    elif bytes != None and (len(self.Afile.readat(None,0)) < offset+length):
      # raise RepyArgumentError
    #   smygloballock['lock'] = release()
      return None
    else:
      try:
        read_data = self.Afile.readat(bytes,offset)
        # mygloballock['lock'] = release()
        return read_data
      except:
        raise RepyArgumentError
        # return None
    # We need some way to release the lock to prevent a deadlock here 
    # self.lock.release
     
  def close(self):
    #Important things to remember when closing a file:
    # Check for file starting with 'S' and ending with 'E'
    # Backup file is a copy of file A
    backup_data_a = self.Afile.readat(None,0)
    data = self.Bfile.readat(None,0)
    backup_file_a = self.Afn
    # We check if file B is valid as S 
    if self.Bfile.readat(None,0).startswith("S") and self.Bfile.readat(None,0).endswith("E"):
      #File B is Valid and Closing A and B
      self.Afile.close()
      self.Bfile.close()
      #Discard File A
      removefile(self.Afn)
      #New Backup File
      openfile(backup_file_a, True).writeat(data,0)
      #Discard File B
      removefile(self.Bfn)
      mycontext['lock'] = release()
    else:
      # If file b is invalid, missing the 'S' and 'E' requirement, then Discard file B, keep file A
      self.Afile.close()
      self.Bfile.close()
      removefile(self.Afn)
      openfile(backup_file_a ,True).writeat(backup_data_a,0)
      removefile(self.Bfn)
      mycontext['lock'] = release()



def ABopenfile(filename, create):
  return ABFile(filename,create)




# The code here sets up type checking and variable hiding for you.  You
# should not need to change anything below here.
sec_file_def = {"obj-type":ABFile,
                "name":"ABFile",
                "writeat":{"type":"func","args":(str,int),"exceptions":Exception,"return":(int,type(None)),"target":ABFile.writeat},
                "readat":{"type":"func","args":((int,type(None)),(int)),"exceptions":Exception,"return":str,"target":ABFile.readat},
                "close":{"type":"func","args":None,"exceptions":None,"return":(bool,type(None)),"target":ABFile.close}
           }

CHILD_CONTEXT_DEF["ABopenfile"] = {TYPE:OBJC,ARGS:(str,bool),EXCP:Exception,RETURN:sec_file_def,TARGET:ABopenfile}

# Execute the user code
secure_dispatch_module()