# -*- coding: utf-8 -*-


# System Analysis
# ===============
#
# :Script:    systemAnalysis.py
# :Date:      February 1st, 2018
# :Revision:  2.1
# :Copyright: © 2016,2017,2018: Alejandro Cervantes <acervant@inf.uc3m.es>

""" systemAnalysis

   This module performs system analysis for a set of files. 
   Basic method is to scans the training file pairs (clean,stego)
   searching for patterns that are later used to construct a model for
   classification of arbitrary files in one of the aforementioned classes
   
"""

from datetime import datetime
import os

from __builtin__ import False
from collections import deque
from binascii import  hexlify,unhexlify

def getEOF (fileName):
    """ Utility function to retrieve the position of the EOF in a file
    """
    f1=open(fileName,'rb')
    f1.seek(0,2)
    eof1 = f1.tell()
    f1.close()
    return eof1


def measure(func,*args,**kwargs):
    """Very basic measuring function for testing performance
        
        Args:
            func (function): Function that is to be called (no parameters)
            
        Returns:
            long: time spent in the function call
    """
    a=datetime.now()
    func(*args,**kwargs)
    b=datetime.now()
    c=b-a
    return c

def readFileList (baseDir='./',coverDir='Modified',stegoDir='Unmmodified',maxfiles=0,extension='jpg',coverSuffix='',stegoSuffix=''):
    """Utility function that creates a list of pairs (coverFile, stegoFile)
    
        Args:
            in_folder (string): Root folder for both the clean and stego files.
            coverDir (string): Folder with the clean files.
            stegoDir (string): Folder with the stego files.
            maxfiles (int): Maximum number of files to be read.
            extension (string): File extension of files to be read.
            coverSuffix (string): Added to the names in the cover folder
            stegoSuffix (string): Added to the names in the stego folder
            
        Returns:
            list: Each element of the list retrieved is a tuple whose first element is the
                clean file name, and the second is the stego file name
        
        This function first selects each file in the coverDir under baseDir, and searches for the corresponding
        file in the stegoDir also under the same baseDir. Each of the elements of the list returned 
        contains a pair of filenames.
        
    """
    imageDir = os.path.join(baseDir,coverDir)
    fileList = [f for f in os.listdir(imageDir) if f.endswith(extension)]
    fileSet = []
    if (maxfiles>0):
        fileList=fileList[0:maxfiles]
    
    for imageFile in fileList:
        imageName = os.path.splitext(imageFile)[0]
        imageExtension = os.path.splitext(imageFile)[1]
        coverImageFile = os.path.join(baseDir, coverDir, imageName + coverSuffix)+ imageExtension
        stegoImageFile = os.path.join(baseDir, stegoDir, imageName + stegoSuffix)+ imageExtension
        fileSet.append ([coverImageFile,stegoImageFile])
    return fileSet

def readFile (filename,maxlen=32,readBlock=32,vstart=0):
    """Utility function that reads bytes from a file by iteratively reading blocks
    
        Args:
            filename (string): File name
            maxlen (int): Number of blocks to read
            readBlock (int): Bytes in a block
            vstart (int): Offset from the start of the file
    """
    
    fb = open (filename,'rb')
    fb.seek(0,2)
    eof1=fb.tell()
    fb.seek(vstart,0)
    if maxlen==0:
        mx=eof1
    else:
        mx=min(maxlen+vstart,eof1)
    while vstart < mx:
        fileBlock = fb.read(readBlock)
        print ' Read pos [', fb.tell()-readBlock, ']: ', hexlify(fileBlock)
        vstart=vstart+readBlock;

def getHex(b):
    """ Return a list with hex encoded values for a bitarray object
    
        Args:
            b (bitarray): Data to be encoded.
            
        Returns:
            list: List of hexadecimal strings
    """
    s = list (x.encode('hex') for x in b.tobytes())
    return s

def swap_order(d, wsz=4, gsz=2 ):
    """ Utility function that swaps order of bytes to place MSB before LSB when printing.
        To compare with hex dumps from the hexdump tool, chunk size must be 2.
        
        Args:
            d (list): List of bytes to be reordered
            
        Returns:
            string: Reordered word, printable format
    """
    return "".join(["".join([m[i:i+gsz] for i in range(wsz-gsz,-gsz,-gsz)]) for m in [d[i:i+wsz] for i in range(0,len(d),wsz)]])


def getPatternFromConstantMask (m):
    """ Generates a pattern structure from a mask of constant bytes (string)
    
        Patterns have an initial block with the offset for the cover and stego object, then True if both 
        match exactly, then the values read for both cover and stego objetcs
    """
    pattern =  [ ((0,0,0), True, unhexlify(m), unhexlify(m)) ]
    return pattern


def getValuesForPattern(pattern,filename, maxlen=1024,chunk=2,discretize=False,showInfo=False,from_end=False):
    """ This function has two different implementations, one
        for constant patterns, where we just want to know if there is a match
        and other for variable patterns (much slower), where we must extract the list of
        values that replace the variable part, if any
        
        Uses two internal different file search functions, defined later
        
    """
    if from_end:
        fsize = os.path.getsize(filename)
        vstart= fsize-maxlen*chunk
        relativeMaxLen=True
    else:
        vstart=0
        relativeMaxLen=False
        
    sblocks=searchblocks(pattern,True)
    variablePattern = True
    if all (b[0] for b in sblocks): # Only search matches
        variablePattern=False
    if variablePattern:
        valList = getValuesForVariablePattern2(pattern=pattern,filename=filename,maxlen=maxlen,chunk=chunk,showInfo=showInfo,vstart=vstart,relativeMaxLen=relativeMaxLen)
    else:
        valList = [ searchFile(pattern=pattern,filename=filename,maxlen=maxlen,chunk=chunk,vstart=vstart)[0]]
    return valList


def getMaskFromPattern (p,reverse=False,chunk=2):
    """Utility function that encodes a pattern in a readable mask
    
        Args:
            p (pattern): Any element of the list extracted by collectVariablePatternsFromFile
            chunk (integer): Chunk size used to extract the pattern
            
        Return:
            string: Mask where common parts of the patterns are displaid normally, while variable
                parts are replaced with question marks '?'
    """
    mask=[]
    for b in p:
        if b[1]:
            mask.append(hexlify(b[2]))
        else:
            mask.append('??'*chunk)
    return ''.join(mask)


def collectPatternsEOFInjection (fileSet, maxlen=0,headlen=2,varlen=0,taillen=2,chunk=2,from_byte=0):
    """ Gets EOFInjection patterns from a list of files
    """
    
    c={}
    p={}
#    print ("Collecting Patterns from EOF hl:{0}, tl:{1}".format(headlen,taillen))
    for f in fileSet:
        fileName=os.path.basename(f[0])
        c[fileName],p[fileName]=collectPatternsFromEndOfFile(fileClean=f[0],fileStego=f[1],maxlen=maxlen,headlen=headlen,varlen=varlen,taillen=taillen,chunk=2,from_byte=from_byte)
#        print ("Collected masks: {0}".format(p[fileName]))
    return c,p


# ---------------------- END OF EXPORTED FUNCTIONS -----------------------------


# ---------------------- FILE SEARCH FUNCTIONS -----------------------------
def purgeFileList (fileList):
    """ Filters a list of file pairs returning the pairs where both elements actually exist
    """
    
    fileList2 = list ( (c,s) for c,s in fileList if os.path.isfile(c) and os.path.isfile(s))
    return fileList2

def searchFile (filename,pattern,maxlen=0,readBlock=1024,chunk=2,vstart=0):
    """Searches a full file for a pattern
       This is an implementation aimed to fast block search
    
        Args:
            filename (string): Name of the file
            pattern (pattern struct): Pattern searched
            maxlen (int): Search only the first maxlen bytes in the file
            readBlock (int): Number of bytes read in a single call
            vstart (int): Offset from the start of the file
            
        Returns:
            matches: True if there is a match
            matchIndex: Position of the first match
    """
    matches=False
    matchIndex=-1
    sblocks = searchblocks (pattern,True)
    head=[]
    for b in sblocks:
        if b[0]:
            head+=b[1]
        else:
            # Break on any non True block
            break;
    findString=''.join(head)
    patternLength=len(head)*chunk
    if (maxlen>0) and (maxlen<patternLength):
        raise RuntimeError ("searchFile requires a value of maxlen at least equal to pattern length")
    fb = open(filename, "rb")
#    vstart=0
    fb.seek(0,2)
    eof1=fb.tell()
    fb.seek(vstart,0)
    if maxlen==0:
        mx=eof1
    else:
        mx=min(maxlen+vstart,eof1)
#    print 'Stating search with mx:', mx, ' EOF: ', eof1, ' Starting at: ', vstart
    while vstart < mx:
#        print ' File position before: ', fb.tell(), ' max:', mx
        fileBlock = fb.read(readBlock)
        actualRead=len(fileBlock)
#        print ' File position after read: ', fb.tell(),' read ', actualRead, ' bytes'
        filePos = fileBlock.find(findString) 
        if (filePos >= 0):
            matches=True
            matchIndex=fb.tell()-actualRead+filePos
            break;
        if fb.tell()>=mx:
            break
        else:
#            print ' Pattern length:', patternLength
            vstart=vstart+actualRead-patternLength;
#            print ' File position before change', fb.tell()
            fb.seek(vstart,0)
#            print ' File position after change: ', fb.tell()
        
        
    return matches,matchIndex

def getValuesForVariablePattern2(pattern,filename,maxlen=1024,chunk=2,showInfo=False,vstart=0,relativeMaxLen=False):
    """Searches a full file for a pattern and retrieves the concatenated values found for the variable parts
       This is an implementation aimed to fast block search
    
        Args:
            filename (string): Name of the file
            pattern (pattern struct): Pattern searched
            maxlen (int): Search only the first maxlen bytes in the file
            readBlock (int): Number of bytes read in a single call
            vstart (int): Offset from the start of the file
            showInfo (boolean): Display debug information
            relativeMaxLen (boolean): Maxlen counts from vstart
            
        Returns:
            Values found in the file (list) (more than one match may be found)
    """

    patternMatches=[]
    if showInfo:
        print 'Checking against file ', filename, ' with maxlen: ', maxlen
        printPattern (pattern,chunk=2,reverse=False)

    sblocks = searchblocks (pattern,True)
    fdesc = None
#    vstart = 0
    matched = True
    """
        Sequentially extract a block and either search for its location or accumulate its value
        We do this as long as it is matched, because each file can provide several different values
        
        TODO: Deep revision of the process of reading blocks and moving pointers. Unneeded iterations
        have been detected.
    """
    value=[]
    while matched:
        matched=False
        readBack=-1
        for b in sblocks:
            if showInfo:
                print 'Next block of type:', b[0], ' and value: ', b[1]
            searchValue=''.join(b[1])
            if b[0]: # Block to match
                if showInfo:
                    print 'Searching string ', valueToString(b[1]), ' of type: ', type(b[1])
                    
                # This reads the file from the vstart position until a match is found
                loc,fdesc,vstart = searchValueInFile(value=searchValue,filename=filename,
                                                     fileDesc=fdesc,vstart=vstart,maxlen=maxlen,showInfo=showInfo,
                                                     relativeMaxLen=relativeMaxLen)
                
                if loc < 0:
                    matched = False
                    value=[]
#                    vstart-=len(searchValue)*chunk
                    # As blocks are mandatory, if unmatched we exit with a failure
                    break;
                else:
                    # We just set the matched flag. We shall used the former loc,fdesc and vstart to continue
                    matched = True
                    if showInfo:
                        print 'Found the search value at position: ', loc
                    if readBack > 0:
                        fdesc.seek(loc-readBack)
                        v = fdesc.read (readBack)
                        vstart = loc + readBack
                        value += v
                        readBack=-1
                        if showInfo:
                            print 'Reading delayed value: ' , hexlify(v)
                    else:
                        loc = loc + len(b[1])*chunk
                        fdesc.seek(loc)
                        if showInfo:
                            print 'Moved reading pointer to position: ', loc
                        
            else: # Block to store
                if not fdesc:
                    # If the descriptor is None, then we have to open the file
                    fdesc = open (filename,'rb')
                    readBack = len(searchValue)
                    vstart=readBack
                    if showInfo:
                        print 'We have to perform backwards search of : ' , len(searchValue) , ' bytes'
                else:
                    loc = fdesc.tell()
                    if showInfo:
                        print 'Grabbing value from position: ', loc, ' of length ', len(searchValue)

                    v       = fdesc.read (len(searchValue))
                    vstart  = loc + len(searchValue)
                    value  += v
                    if showInfo:
                        print 'Reading partial value: ' , hexlify(v)

        if len(value)>0:
            if value not in patternMatches:
                patternMatches.append(list(value))
                if showInfo:
                    print 'Adding value: ' , value
            else:
                if showInfo:
                    print 'Repeated value: ' , value
                
            value=[]
            
#            break; # Break here if we need a single value

#    if showInfo:
#        print 'Matches: ', valuesToHexList(patternMatches)
        
    fdesc.close()
    
    return patternMatches
            
        
            
        
def collectVariablePatternsFromFile(fileClean,fileStego,maxlen=0,headlen=2,varlen=-1,taillen=2,
                            chunk=2,from_byte_1=0,fromEndOfCover=False,fromStartOfDifferences=False,
                            from_byte_2=0,showInfo=False,hexformat=False):
    """Collect all the patterns that can be found comparing two files.
        Note: this comment block may be out of date (Feb 2nd, 2018)
        
        A pattern is defined by one of the following structures:
            <HEAD><VARIABLE-DATA><TAIL>
            <HEAD><VARIABLE-DATA>
    
        Args:
            fileClean (string): Path and filename for the clean file.
            fileStego (string): Path and filename for the stego file.
            maxlen (long): Maximum length of data being read from files (in bytes).
            headlen (int): Maximum length in chunks of the pattern head.
            varlen (int): Maximum length in chunks of any variable part , -1 means no limit
            tailllen (int): Maximum length in chunks of the pattern tail.
            chunk (int): Chunk size.
            from_byte_1 (long): Move to this point in the first file before comparison.
            from_byte_2 (long): Move to this point in the second file before comparison.
            fromEndOfCover (bool): Set from_byte to the EOF of the clean file (NOT QUITE TESTED)
            showInfo (bool): Show debugging information
            hexformat (bool): If True, encode values in hexadecimal, else, store bytes.
            
        Returns:
            list: each element is a tuple of the status (True means values are equal), value from the clean
                file and value from the stego file. Values are bytes, except if hexformat=True
            
        This function collects patterns by comparing two files. 
        Chunk size is the number of bytes (16-bits) that are read and compared.
        Also header and tail lenghts are measured in chunks.
        A chunk size of 2 correspondss to the normal 32/bit word for hexdump.
        Once a pattern starts, it may contain unchanged chunks but pattern does not stop
        until an unmodified contiguous block of taillen chunks is found.
        Once a tail block is found, the pattern is stored. File is returned to the tail start
        using seek(), because this might be the start of a new pattern.
        Use printpattern to print the results of pattern collection.
        
        Automata state is the section variable:
            section=-1, before starting a pattern
            section=0, reading the head of a pattern
            section=1, reading a variable part of a pattern
            section=2, reading the tail of a pattern
            
            -1,status  => 0
            0,status   => 0 if hlen <  headlen
            0,!status  => 1 if hlen >= headlen
            0,!status  => -1 if hlen < headlen (???) debug this
            1,status   => 2
            1,!status  => 1
            2,status   => 2 if mlen < taillen
            2,status   => 0 if mlen >= taillen (stores pattern and head <- tail)
            
    """

    res=[]
    with open(fileClean, "rb") as f1, open(fileStego, "rb") as f2:
        try:
#            print '        Collecting patterns for files:' , fileClean, ',' , fileStego
            f1.seek(0, 2)
            eof1 = f1.tell()
            f1.seek(0, 0)
            f2.seek(0, 2)
            eof2 = f2.tell()

            
            """
                To detect code injection, we have to set fromEndOfCover and a varlen!=0
                Thus, a pattern will be stored with some null bytes at the end
            """
            if fromEndOfCover: # This attempts to find code injection at the end of the file
                from_byte_1=eof1-maxlen+varlen*chunk
                from_byte_2=eof1-maxlen+varlen*chunk
                
#            print 'Start search in bytes:' , from_byte_1, ',' , from_byte_2
                
#            print 'File size for f1: ' , eof1
#            print 'File size for f2: ' , eof2
            i=0
            pattern= deque()
            section=-1
            hlen = 0
            vlen=0
            tlen = 0

            """
                Skip sections of the file that are identical
            """
            if fromStartOfDifferences:
                f1.seek(from_byte_1, 0)
                f2.seek(from_byte_2, 0)
                b1 = f1.read(chunk)
                b2 = f2.read(chunk)
                limit = min(eof1,eof2)
                while (b1==b2) and (i<limit):
                    b1 = f1.read(chunk)
                    b2 = f2.read(chunk)
                    i+=chunk
                    
                if (i>=limit):
                    print 'We have reached the value i=',i
                    print 'Limit was:', limit
                    print 'Values read: b1=', hexlify(b1), ' ,b2=', hexlify(b2)
                    raise RuntimeError("collectVariablePatternsFromFile: Files %s and %s are equal", fileClean, fileStego)
                    
                from_byte_1 = max(f1.tell() - headlen*chunk,from_byte_1)
                from_byte_2 = max(f2.tell() - headlen*chunk,from_byte_2)
                print ' Position of first difference:', i, ' rewind to:', from_byte_1, ",", from_byte_2
                if maxlen>0:
                    maxlen=i+maxlen
                    
                
            mx = min(eof1,eof2,maxlen)
            f1.seek(from_byte_1, 0)
            f2.seek(from_byte_2, 0)
            
            while (maxlen==0) or (i < mx):
                r1 = eof1-f1.tell() 
                r2 = eof2-f2.tell()
                if (r1 == 0) and (r2 == 0):
                    if showInfo:
                        print 'Found the end of BOTH files'
                    break;


                
                """
                    When one of the files has reached EOF we will include special marks in the pattern
                    Note that the last value read may be less than chunk in size
                """
                eofCode='\xFF'
                if r1 > 0:
                    b1 = f1.read(chunk)
                    if len(b1)<chunk:
                        for i in range(chunk-len(b1)):
                            b1 += eofCode
                else:
                    if showInfo:
                        print 'Found the end of the clean file'
                    b1 = eofCode*chunk
                if r2 > 0:
                    b2 = f2.read(chunk)
                    if len(b2)<chunk:
                        for i in range(chunk-len(b2)):
                            b2 += eofCode
                else:
                    if showInfo:
                        print 'Found the end of the stego file'
                    b2 = eofCode*chunk
                
                # STATUS is the automata input
                #
                # status is TRUE if both bytes are equal
                # status is FALSE if both bytes are not equal
                # status is FALSE if one of the files has finished
                #
                # This is stored in the pattern first field
                # Byte format in the pattern is: position, status,b1,b2

                status = (b1 == b2) and (r1>0) and (r2>0)

                if showInfo:
                    print ' Reading position: i:', hex(i), ' b1:', hexlify(b1), ' b2:', hexlify(b2)
                    print ' Read : sect=', section , ' stat=', status, ' pat=', getMaskFromPattern(pattern), ' hlen= ', hlen, ' vlen= ', vlen, ' tlen=', tlen
                
                #
                # pattern is a holding area for the last chunks read, that may
                # store as many values as required (except if varmax is set to nonzero)
                # If reading a head only stores the headlen last chunks
                # After reading a head, stores everything until the pattern is finished
                #
                if (section > -1) or status:
                    if hexformat:
                        pattern.append (((i,i+from_byte_1,i+from_byte_2),status,hexlify(b1),hexlify(b2)))
                    else:
                        pattern.append (((i,i+from_byte_1,i+from_byte_2),status,b1,b2))
                    
                if status:
                    if section==-1: # Start a head
                        section=0
                        hlen=0
                    if section==0: # Accumulate p to hlen chunks
                        if hlen >= headlen:
                            pattern.popleft()
                        else:
                            hlen+=1
                    if section==1: # Pattern is finished, start with tail
                        section=2
                        tlen=0
                    if section==2: # Accumulate up to tlen chunks
                        tlen+=1
#                        print 'Current tlen: ', tlen
                        if tlen >= taillen:
                            # Here we move back so the tail can become the next head
                            f1.seek(-tlen*chunk,1)
                            f2.seek(-tlen*chunk,1)
                            i-=tlen*chunk
                            section=0
                            tlen=0
                            hlen=0
                            res.append(list(pattern))
                            if showInfo:
                                print ' Store pattern=', getMaskFromPattern(pattern)
                            pattern= deque()
                else:
                    if section==0:
                        if (hlen < headlen):
                            hlen=0
                            vlen=0
                            tlen=0
                            section=-1
                            pattern=deque()
                        else:
                            # Start a variable section
                            section=1
                        vlen=0
                        
                    if section==2:
                        # Exploring the tail we find a variable section
                        section=1
                        tlen=0
                        vlen=0
                    if section==1:
                        # Found variable data, minimum length is 1
                        vlen+=1
                        if varlen>0: 
                            # Check patterns where variable block is too long
                            if vlen>varlen:
                                # Stop
                                section=-1
                                tlen=0
                                vlen=0
                                hlen=0
                                res.append(list(pattern))
                                if showInfo:
                                    print ' Store pattern=', getMaskFromPattern(pattern)
                                pattern= deque()
                            
                if showInfo:
                    print ' Next : sect=', section , ' stat=', status, ' pat=', getMaskFromPattern(pattern), ' hlen= ', hlen, ' vlen= ', vlen, ' tlen=', tlen
                i+=chunk
        finally:
#            print 'End search for files:' , fileClean, ',' , fileStego
            f1.close()
            f2.close()
    return res




def searchValueInFile (value,filename=None,maxlen=0,readBlock=1024,vstart=0,fileDesc=None,relativeMaxLen=False,showInfo=False):
    """Searches a full file for a pattern, retrieves first position found for a value
    
        Returns the open file descriptor with the position of the found value. That means
        that the calling code can restart the search by recalling this method without
        reopening the file.
        
        Args:
            value (list): List of bytes to find
            filename (string): Name of the file to open (if not already opened)
            maxlen (long): Maximum position read from the file
            readBlock (int): Size of the block being read from the file
            vstart (long): Displacement from the start of the file (to continue reading)
            fileDesc (file descriptor): Opened file descriptor
            relativeMaxLen (boolean): 
                If True, we read up to maxlen values starting from the vstart position
                If False, maxlen is considered to start at the initial position of the file
            showInfo (bool): If true, display debugging information
            
        Returns:
            fIndex,fb,vstart: Retrieved data.
    """

    # Set the start of the file to the proper position
    # if fileDesc is not open, open it now
    if not fileDesc:
        if not filename:
            raise RuntimeError ("searchFile2 requires either a filename or a file descriptor")
        fb = open(filename, "rb")
    else:
        fb = fileDesc
        
    fb.seek(0,2)
    eof1=fb.tell()
    fb.seek(vstart,0)
    
    # Set the end of the search
    if maxlen==0:
        mx=eof1
    else:
        if relativeMaxLen:
            mx=min(maxlen+vstart,eof1)
        else:
            mx=min(maxlen,eof1)
        
    fIndex=-1
    if showInfo:
        print 'FB opened, mx=' , mx, ' eof=', eof1, ' start search at vstart=', vstart
    while vstart < mx:
        if showInfo:
            print '  Start block read at ', fb.tell(), ' mx=', mx
        fileBlock = fb.read(readBlock)
#        if showInfo:
#            print '  Read =', hexlify(fileBlock)
        actualRead=len(fileBlock)
        filePos = fileBlock.find(value) 
        found = ( filePos >= 0)
        if found:
            if showInfo:
                print '  Found block at position: ', filePos, ' rewind file to that position'
            fIndex=fb.tell()-actualRead+filePos
            fb.seek(fIndex,0)
            if showInfo:
                print '  FOUND: Moved file pointer to ', fb.tell()
            break;
            vstart=vstart+actualRead-len(value);
            fb.seek(vstart,0)
        else:
            vstart=vstart+actualRead;
            fb.seek(vstart,0)
            if showInfo:
                print '  NOT FOUND: Moved file pointer to ', fb.tell(), ' mx=', mx, ' actualRead=', actualRead
                print '  NOT FOUND: Advanced vstart to ', vstart, ' mx=' , mx
                
    return fIndex,fb,vstart

    

def collectPatternsFromEndOfFile(fileClean,fileStego,maxlen=0,headlen=2,varlen=0,taillen=2,chunk=2,from_byte=0,verbose=False):
    """Collect patterns that are only found after the end of file for code injection systems
    
        We move a pattern mask along the part that has been injected and find:
            - Patterns that are in the other files
            - Patterns that are NOT in the smaller file
            - Patterns are going to be exact matches of len=headlen+taillen
            
        Returns:
            Patterns found (list)
            Masks of the patterns found (list)
            
    """
    # print("Parameters: %s",   (fileClean, fileStego))
    # print("Parameters: %s", (maxlen,headlen,varlen,taillen,from_byte))
    res=[]
    pmasks=[]
    with open(fileClean, "rb") as f1, open(fileStego, "rb") as f2:
        try:
#            print 'Start search for files:' , fileClean, ',' , fileStego
            f1.seek(0, 2)
            eof1 = f1.tell()
            f2.seek(0, 2)
            eof2 = f2.tell()
            if eof2 > eof1:
                largerF=f2
                smallerFile=fileClean
                f2.seek(from_byte+eof1, 0)
                f1.close()
                if verbose:
                    print 'Stego file is longer than cover file. Starting at position: ', f2.tell()
            else:
                if eof1>eof2:
                    largerF=f1
                    smallerFile=fileStego
                    f1.seek(from_byte+eof2, 0)
                    f2.close()
                    if verbose:
                        print 'Clean file is longer than cover file. Starting at position: ', f1.tell()
                else:
                    if verbose:
                        print 'EXITING, files are of equal length. Try another method'
                    return res,pmasks
                
            
            # At this point the smaller file starts at its start (plus from_byte)
            # And the larger file starts in the point it should end
            pattern= deque()
            largerEOF = max(eof1,eof2)
            mx=min(largerEOF,min(eof1,eof2)+maxlen)
            while (maxlen==0) or (largerF.tell() < mx):
                patternSizeChunks=headlen+taillen
                i=largerF.tell()
                b1 = largerF.read(chunk)
                pattern.append ((i,True,b1,b1))
                if len(pattern)>=patternSizeChunks:
                    pmask=getMaskFromPattern(pattern)
                    if verbose:
                        print ' Trying pattern:', pmask
                    if not pmask in pmasks:
                        # Check the pattern against the clean part
#                        print ' Testing a pattern against the smaller part'
#                        matches = searchBitarray(smallerFile,pattern,chunk=chunk)
#                        if len(matches)==0:
                        matches = searchFile(smallerFile,pattern,chunk=chunk)[0]
                        if not matches:
                            if verbose:
                                print ' No match found in the smaller part'
                            res.append(list(pattern))
                            pmasks.append(pmask)
                            # Skip half of the pattern
#                            for i in range(patternSizeChunks/2-1):
#                                pattern.popleft()
                        else:
                            if verbose:
                                print 'Matches found:', matches
                    else:
                        if verbose:
                            print 'Pattern is repeated'
                    # Discard the leftmost part and repeat
                    pattern.popleft()
                
        finally:
            f1.close()
            f2.close()
            
    return res,pmasks

            
        


# ----------------------- PATTERN RELATED INTERNAL FUNCTIONS ---------------------

def flattenListOfList(listOfLists):
    return list ([item for sublist in listOfLists for item in sublist])




def checkValuesForPattern (filenames,pattern,maxlen):
    for filename in filenames:
        print '  File: ', filename
        print '  Pattern: ', getMaskFromPattern(pattern),' ',
        print valuesToHexList(getValuesForPattern(filename=filename,pattern=pattern,maxlen=maxlen))


def checkValuesForPatternList (filenames,patterns,maxlen):
    for f,v in patterns.items():
        print 'Patterns extracted from File: ', f
        for filename in filenames:
            print '  File: ', filename
            for p in v:
                print '  Pattern: ', getMaskFromPattern(p),' ',
                print valuesToHexList(getValuesForPattern(filename=filename,pattern=p,maxlen=maxlen))




def printPattern (p,reverse=False,chunk=2):
    """Utility function that prints a list of patterns
    
        Args:
            p (list): Contains patterns in the format returned by 
            reverse (bool): If True, reverse every word to print MSB first
            chunk (int): Use this chunk size for all operations
            
    """
    clean=[]
    stego=[]
    print 'Pattern at pos: ', list ( hex(v) for v in p[0][0] )
    mask=getMaskFromPattern(p,chunk=chunk)
    for b in p:
#        if b[1]:
#            mask.append(hexlify(b[2]))
#        else:
#            mask.append('??'*chunk)
        clean.append(hexlify(b[2]))
        stego.append(hexlify(b[3]))
    if reverse:
        print 'Clean:   ' , swap_order(''.join(clean))
        print 'Stego:   ' , swap_order(''.join(stego))
        print 'Mask:    ' , swap_order(''.join(mask))
    else:
        print 'Clean:   ' , ''.join(clean)
        print 'Stego:   ' , ''.join(stego)
        print 'Mask:    ' , ''.join(mask)           


def printPatterns (patlist,reverse=False,chunk=2):
    """Utility function that prints each pattern in patlist """

    for i,p in enumerate(patlist):
        print 'Pattern: ' , i
        printPattern (p,reverse=reverse,chunk=chunk)

def printAllPatterns (patdict,reverse=False,chunk=2):
    """Utility function that prints each pattern in a pattern dictionary (for several files) """
    for k,v in patdict.items():
        print 'Extracted from file: ', k
        printPatterns (v,reverse=reverse,chunk=chunk)
        print

def searchblocks(pattern,clean=True):
    """Function used to concatenate the invariable blocks in a pattern
    
        Args:
            clean (bool): If True, return the data part for the pattern as it was found in the
                clean file; else, return the data part from the stego file
                
        list: A sequence of invariant/variant/invariant parts in a pattern
        
        This function is used to join the bytes that compose the header, data, and tail,
        of a pattern.
    """
    sblocks = []
    pblock=[]
    ival=pattern[0][1]
    if clean:
        valindex=2
    else:
        valindex=3
        
    for b in pattern:
        if b[1]==ival:
            pblock.append (b[valindex])
        else:
            sblocks.append((ival,pblock))
            ival = not ival
            pblock = [b[valindex]]
    sblocks.append((ival,pblock))
    return sblocks

def valueToString (v):
    """Utility function that hexlifies a list """
    return list( hexlify(b) for b in v )

def valuesToHexList (valueList):
    """Utility function that joins the hexlified values of a list """
    return list ( ''.join(valueToString(v)) for v in valueList )


# ---------------------- INTERNAL PATTERN COLLECTION FUNCTIONS -----------------------------



            
def collectPatternsMethod1 (fileSet,maxlen=1024,chunk=2,headlen=2,varlen=0,taillen=2,from_byte=0,fromEndOfCover=False,fromStartOfDifferences=False):
    """Collects a dictionary of patterns from several files
    
        Args:
            fileSet (list): A list of tuples with pairs of files [(clean,stego),]
            
        Returns:
            dict: Dictionary, key is the file base name and value the list of patterns
    
    """
    c={}
    for f in fileSet:
        fileName=os.path.basename(f[0])
        c[fileName]=collectVariablePatternsFromFile(fileClean=f[0],fileStego=f[1],maxlen=maxlen,
            chunk=chunk,headlen=headlen,varlen=varlen,taillen=taillen,
            from_byte_1=from_byte,fromEndOfCover=fromEndOfCover,fromStartOfDifferences=fromStartOfDifferences)
    return c


def collectPatternsMethod5 (fileSet,maxlen=1024,chunk=2,headlen=2,varlen=0,taillen=2):
    """Collects a dictionary of patterns from several files
        This method is like Method 1 but searches the last maxlen bytes of the file
    
        Args:
            fileSet (list): A list of tuples with pairs of files [(clean,stego),]
            
        Returns:
            dict: Dictionary, key is the file base name and value the list of patterns
    
    """
    c={}
    for f in fileSet:
        fileName=os.path.basename(f[0])
        eof1=getEOF(f[0])
        eof2=getEOF(f[1])
        c[fileName]=collectVariablePatternsFromFile(fileClean=f[0],fileStego=f[1],maxlen=maxlen,
            chunk=chunk,headlen=headlen,varlen=varlen,taillen=taillen,from_byte_1=eof1-maxlen,from_byte_2=eof2-maxlen)
    return c






