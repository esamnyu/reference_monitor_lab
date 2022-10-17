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

mycontext['lock']= createlock()
class ABFile():
    def __init__(self,filename,create):
        # globals
        mycontext['debug'] = False   
        # local (per object) reference to the underlying file
        self.Afn = filename+'.a'
        self.Bfn = filename+'.b'
        # log(self.Afn, self.Bfn)
        # make the files and add 'SE' to the readat file...
        if create:
            self.Afile = openfile(self.Afn,create)
            self.Bfile = openfile(self.Bfn,create)
            self.Afile.writeat('SE', 0)

# What exactly defines the EOF for a file? Is it the existing data in a file?
# If the offset or the length of the data is greater than the length of the existing data in a file, then this is False
# The pre-defined length of a file is always 2, assuming that "SE" is written in the file
# This is because a check for "SE" occurs      
    def writeat(self,data,offset):
        """
            if len(data) <= len(self.Bfile.readat(None, 0)): 
        if Bfile.readat(1, 0)) == 'S':
            self.Bfile.writeat(data, offset+1)
            self.Bfile.writeat('E', last_character_e)
        """
        # Write the requested data to the B file using the sandbox's writeat call
        #Check if the length of the string in the current file is less then the data being written to the file
        if len(self.Bfile.readat(None, 0)) < len(data):
            return None
        #Check if the length of the string in the current file is less than the offset of the novel data   
        if len(self.Bfile.readat(None, 0)) < offset:
            return None  
        if len(data) <= len(self.Bfile.readat(None, 0)): 
            self.Bfile.writeat(data,offset)

  
    def readat(self,bytes,offset):
        # Read from the A file using the sandbox's readat...
            return self.Afile.readat(bytes,offset)
        # This closes an open file  
        # Requirement 2: Before the file can be closed, we must check if the first chaaracter is a S and the last chaaracter is an E 
        
        # When close() is called on the file, if both filename.a and filename.b are valid, the original file's data 
        # is replaced with the data of filename.b. If filename.b is not valid, no changes are made.
        # After closing the file, lock the file  
    def close(self):
    
        #Write a check for the close function 

        bool valid_a 
        bool valid_b
            #Check to make sure these are actually reading at the beginning and the end of their respective files 
        first_characterA = self.Afile.readat(1, 0)
        last_characterA = self.Bfile.readat(None, 0)-1
        first_characterB = self.Bfile.readat(1, 0)
        last_characterB = self.Afile.readat(None, 0)-1


        if first_characterA == 'S' and last_characterA == 'E':
            valid_a = True 
        if first_characterB == 'S' and last_characterB == 'E':
            valid_b = True

        contents_b = self.Bfile.readat(None, 0)

        if valid_a and valid_b == True:
            self.Afile.writeat(contents_b, 0)
            self.Afile.close()
            self.Bfile.close()

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

