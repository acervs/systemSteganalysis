'''
    Todo: hay que asegurarse de que el chunk size esta correcto cuando
    se buscan patterns en las que no hemos tenido en cuenta este parametro
    Si se examina el modelo veremos que no se leen bien los valores para los patterns
    Empezar por ese punto, probablemente basta con poner chunk size =1
'''
from systemAnalysisUtils import searchValueInFile
from binascii import  hexlify,unhexlify
from collections import Counter

import logging
import os
import sys
from __builtin__ import False

#logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
#logging.basicConfig(filename=opt.logFile,level=opt.debugLevel,filemode='w')

def getSuperMasks (maskList):
    '''This is used to remove from any list of masks the ones that are contained in longer ones
    '''
    superMasks = list()
    for i in maskList:
        superi = list(k for k in maskList if (not i==k) and k.find(i)>=0)
        counti = len(superi)
        if counti==0:
#            print ('Pattern {0} has no superpatterns'.format(i))
            superMasks = superMasks + [i]    
            
    return superMasks
                
def refineModel (model,tsize,type=3,minVals=10):
    '''
        Basic refining
        - Always: Delete void patterns
        - Always: Delete patterns whose probability table is equal
        
        Depending on type:
        - Minimal(3): Delete patterns whose values seem random
        - Medium(2): Keep only patterns that were found in either all the training OR all the testing files
        - Aggressive(1): Do not use. Keep only patterns found in both all training AND testing files
    '''
    # Get rid of void patterns
    mod = { k:model[k] for k,v in model.items() if len(v[1][0])>1 or len(v[1][1])>1  }

    ptable = getProbabilityTable(mod,doPrint=False)
    
    # Get rid of patterns whose probability table is the same for both classes
    mod = { k:v for k,v in mod.items() if not (ptable[k][0]==ptable[k][1]) }



    if (type==1): # Aggressive
        mod = { k:model[k] for k,v in model.items() if len(v[1][0])>=tsize and len(v[1][1])>=tsize  }
    else:
        if (type==2): # Medium
            mod = { k:model[k] for k,v in model.items() if len(v[1][0])>=tsize or len(v[1][1])>=tsize  }
        else:
            if (type==3):
                # Get rid of patterns that have too many values (more than 10 in both classes): both are random
                mod = { k:v for k,v in mod.items() if len(ptable[k][0])<minVals or len(ptable[k][1])< minVals}
            
    return mod

def buildRawModelFromMasks (maskSet, fileSet,maxlen=0,chunk=2,from_end=False,useMatchingAsValue=True):
    """Constructs a model from a mask list
    
        Args:
            maskSet (list): A dictionary of pattern lists such as the one returned by collectPatterns.
            fileSet (list): A list of tuples with pairs of files [(clean,stego),]
            maxlen (long): Maximum length that will be scanned in each file
            chunk (int): Chunk size for reading and interpreting pattern elements
            from_end (bool): Explore the last maxlen bytes of the file
            useMatchingAsValue (bool): Include the value False if a pattern does not match a file

        Returns:
            model (dict): Dictionary that includes the pattern masks, pattern, and values found in matching

            A model is a dictionary whose key is the mask composed from a pattern with getMaskFromPattern.
            Each value of the dictionary is a tuple where:
                The first element is the complete pattern (in the pattern format).
                The second element is a list: 
                    Each element of this list is the list of values found for a given class of files.
                    Currently this list has two elements: 
                        first, list of values for the clean files;
                        second, list of values for the stego files.
                    IMPORTANT NOTE All values found are considered equal, regarless of the fact that they were found
                    in the same file or not
                    NOTE: If a value is composed of different parts, they are concatenated in order
                    
            Examples:
                Number of matches of a pattern p in the clean (class 0) files: model[p][1][0]
                Mask ABAB??00??A0A0 on data ABAB110022A0A0 gives [1122] 
                Mask ABAB??00??A0A0 on data ABAB110022A0A0ABAB330044A0A0 gives model[p][1][class]=[1122,3344] 
                Mask ABAB??00??A0A0 on data ABAB110022A0A0 in file 1 
                Mask ABAB??00??A0A0 on data ABAB330044A0A0 in file 2 gives also model[p][1][class]=[1122,3344]
            
        Model construction is made by storing the values found in either clean or stego versions
        of a file for each of the data parts of each of the patterns in a pattern set.
        Duplicate patterns are only searched once.
        
    """
    model={}
    
    # Now match each pattern against each file  
    for f,mlist in maskSet.items():
#        print '  Patterns extracted from file:' , f
        for pmask in mlist:
            if not (pmask in model.keys()):
#                print '    Checking pattern: ' , pmask
                
                patternMatches=[[],[]] # Count for clean, then stego
                
                for filePair in fileSet:
                    for filetype in range(2): # Check against clean, then stego
#                        print '      Checking file: ' , filePair[filetype]
#                        print '.',
                        valList = getValuesForMask(pmask,filename=filePair[filetype],maxlen=maxlen,chunk=chunk,from_end=from_end,markMatches=useMatchingAsValue)
#                        patternMatches[filetype].append(valList) # This would make a more powerful structure
                        patternMatches[filetype]+=valList
        
                model[pmask]=((),patternMatches)   
#            else:
#                print '    Repeated pattern: ' , pmask, ' ... SKIPPING'
                
#            print
                
    return model 

        
        

def getValuesForMask(mask,filename, maxlen=0,chunk=2,from_end=False,markMatches=False):
    """getValuesForMask
    
        This function has two different implementations, one
        for constant patterns, where we just want to know if there is a match
        and other for variable patterns, where we must extract the list of
        values that replace the variable part, if any
    """
    logging.debug ("Searching values for mask:", mask)
    if from_end:
        fsize = os.path.getsize(filename)
        vstart= fsize-maxlen*chunk
        relativeMaxLen=True
    else:
        vstart=0
        relativeMaxLen=False
        
    sblocks=splitMaskInBlocks(mask)
    variablePattern = True
    if all (b[0]==0 for b in sblocks): # Only search matches
        variablePattern=False
        
    if variablePattern:
        valList = getValuesForVariableMask(mask=mask,filename=filename,maxlen=maxlen,chunk=chunk,vstart=vstart,
                                           relativeMaxLen=relativeMaxLen,markMatches=markMatches)
    else:
        valList = [ searchStringInFile(cnststr=mask,filename=filename,maxlen=maxlen,chunk=chunk,vstart=vstart)[0]]
    return valList

def searchStringInFile (cnststr,filename,maxlen=0,readBlock=1024,chunk=2,vstart=0):
    """Searches a full file for a constant hex string
    
        Args:
            
        Returns:
            bitarray: Retrieved data.
    """
    matches=False
    matchIndex=-1
    try:
        findString=unhexlify(cnststr)
    except:
        raise RuntimeError("error in unhexlify of ", cnststr)
    patternLength=len(findString)*chunk
    
    if (maxlen>0) and (maxlen<patternLength):
        raise RuntimeError ("searchFile requires a value of maxlen at least equal to pattern length")
    
    fb = open(filename, "rb")
    fb.seek(0,2)
    eof1=fb.tell()
    fb.seek(vstart,0)
    if maxlen==0:
        mx=eof1
    else:
        mx=min(maxlen+vstart,eof1)
    while vstart < mx:
        fileBlock = fb.read(readBlock)
        actualRead=len(fileBlock)
        filePos = fileBlock.find(findString) 
        if (filePos >= 0):
            matches=True
            matchIndex=fb.tell()-actualRead+filePos
            break;
        if fb.tell()>=mx:
            break
        else:
            vstart=vstart+actualRead-patternLength;
            fb.seek(vstart,0)
        
        
    return matches,matchIndex


def splitMaskInBlocks(mask,maskChar='?',skipChar='*'):
    """Function used to split a mask in constant and variable parts
    
        Args:
            mask: A mask, variable part replaced by special characters
                
        list: The mask split in blocks of constant/ignored/value sections
        
        Each value in the list is marked with a flag.
        Value is always an hex string. It will later be converted to a list of bytes.
        Special marks are thus coded as hex strings, but because the block is not
        of constant type, this value is not to be used anywhere else. We only set it
        to set the total length of this block in a consistent way.
    """
    sblocks=[]
    pblock=[]
    
    if mask[0]==maskChar:
        blockType=2
    else:
        if mask[0]==skipChar:
            blockType=1
        else:
            blockType=0
        
    for b in mask:
        # Decide if we are continuing a block or we have to store and change
        if b==maskChar: # Corresponds to start of blockType 2
            if blockType==0:
                sblocks.append((0,''.join(pblock)))
                pblock=[]
            else:
                if blockType==1:
                    sblocks.append((blockType,'1'*len(pblock)))
                    pblock=[]
            blockType=2
        else:
            if b==skipChar: # Corresponds to start of blockType 1
                if blockType==0:
                    sblocks.append((0,''.join(pblock)))
                    pblock=[]
                else:
                    if blockType==2:
                        sblocks.append((blockType,'2'*len(pblock)))
                        pblock=[]
                blockType=1
            else: # Hexadecimamal character
                if blockType==1:
                    sblocks.append((blockType,'1'*len(pblock)))
                    pblock=[]
                else:
                    if blockType==2:
                        sblocks.append((blockType,'2'*len(pblock)))
                        pblock=[]
                blockType=0
        pblock.append (b)

    if len(pblock)>0:
        if blockType==1 or blockType==2:
            sblocks.append((blockType,str(blockType)*len(pblock)))
        else:
            sblocks.append((blockType,''.join(pblock)))
            
    return sblocks

def getValuesForVariableMask(mask,filename,maxlen=0,chunk=2,vstart=0,relativeMaxLen=False,markMatches=False):
    patternMatches=[]

    sblocks = splitMaskInBlocks (mask)
    fdesc = None
#    vstart = 0
    matched = True
    """
        Sequentially extract a block and either search for its location or accumulate its value
        We do this as long as it is matched, because each file can provide several different values
        
        TODO: Deep revision of the process of reading blocks and moving pointers. Unneeded iterations
        have been detected.
    """
#    value=[]
    matchedOnce=False
    continueSearch=True
    while continueSearch:
        readBack=-1
        logging.debug ("Start a new search for the mask: {}".format(mask) )
#        print ("Start a new search for the mask: {}".format(mask) )
        constantBlockNumber=0
        value=[]
        for b in sblocks:
            logging.debug ("Next block of type: {} and value: {}".format( b[0],b[1] ) )
#            print ("Next block of type: {} and value: {}".format( b[0],b[1] ) )
            searchValue=unhexlify(''.join(b[1]))
            if b[0]==0: # Block to match
                
                if constantBlockNumber>0: # We are inside a pattern and we have to find the block exactly in this position
                    # Localization for this search is the current position (we don't search the block in a general location)
                    loc = fdesc.tell()
                    v       = fdesc.read (len(searchValue))
                    logging.debug ("Searching constant {} at position {}: {}".format( hexlify(searchValue),loc,hexlify(v)) )
#                    print ("Searching constant {} at position {}: {}".format( hexlify(searchValue),loc,hexlify(v)) )
                    if v == searchValue:
                        matched=True
                        constantBlockNumber+=1
                        # Vstart is used in case we exit the function
                        vstart  = loc + len(searchValue)
                        # Continue with next block
                    else:
                        # This is questionable. We restart the search at the end of the last block we were searching
                        matched=False
                        vstart  = loc
                        fdesc.seek(loc,0)
                        # Break the loop and start the search again in the previous location (lastLoc)
                        break;
                    
                else: # We have not yet found a pattern match so we search anywhere    
                    # This reads the file from the vstart position until a match is found
                    constantBlockNumber=1
                    loc,fdesc,vstart = searchValueInFile(value=searchValue,filename=filename,
                                                         fileDesc=fdesc,vstart=vstart,maxlen=maxlen,
                                                         relativeMaxLen=relativeMaxLen)
                    
                    if loc < 0:
                        matched = False
                        value=[]
                        logging.debug ("Reached the end of the file while searching for: {}".format( hexlify(searchValue) ) )
#                        print ("Reached the end of the file while searching for: {}".format( hexlify(searchValue) ) )
                        continueSearch=False
    #                    vstart-=len(searchValue)*chunk
                        # As blocks are mandatory, if unmatched we exit with a failure
                        break;
                    else:
                        # We just set the matched flag. We shall used the former loc,fdesc and vstart to continue
                        matched = True
                        logging.debug ("Found the constant search value {} at position: {}".format(hexlify(searchValue), loc) )
#                        print ("Found the constant search value {} at position: {}".format(hexlify(searchValue), loc) )
                        if readBack > 0:
                            logging.debug ("Reading delayed from position %s a total of %s bytes", loc, readBack)
                            if loc>readBack:
                                # We go back to the position where we had to read the value,
                                # and later we advance again to this position
                                currentpos=fdesc.tell()
                                fdesc.seek(loc-readBack,0)
                                v = fdesc.read (readBack)
                                value += v
                                logging.debug ("Grabbing delay value from position {} of length {}: {}".format(loc,readBack, hexlify(v)) )
#                                print ("Grabbing delay value from position {} of length {}: {}".format(loc,readBack, hexlify(v)) )
                                readBack=-1
                            else:
                                logging.debug ("We can't find %s values before position %s", readBack,loc)
                                
                        # We have found the first constant block at loc, advance and proceed to the next one
                        vstart = loc + len(searchValue)
                        fdesc.seek(vstart)
                        # We store the end of the constant block to start the new search here.
                        logging.debug ("Reading pointer is at position: {}".format(fdesc.tell()) )
#                        print ("Reading pointer is at position: {}".format(fdesc.tell()) )
                        
            elif b[0]==1: # Block to skip
                    if not fdesc:
                        # If the descriptor is None, then we have to open the file
                        fdesc = open (filename,'rb')
                    loc = fdesc.tell()
                    v       = fdesc.read (len(searchValue))
                    vstart  = loc + len(searchValue)
                    logging.debug ("Skipping at position {} a block of length {}".format(loc, len(searchValue) ))
#                    print ("Skipping at position {} a block of length {}".format(loc, len(searchValue) ))

            elif b[0]==2: # Block to store
                    if not fdesc:
                        # If the descriptor is None, then we have to open the file
                        fdesc = open (filename,'rb')
                        readBack = len(searchValue)
                        vstart = readBack
                        logging.debug ("We have to perform backwards search of %s bytes", readBack)
                    else:
                        loc = fdesc.tell()
    
                        v       = fdesc.read (len(searchValue))
                        vstart  = loc + len(searchValue)
                        value  += v
                        logging.debug ("Grabbing value from position {} of length {}: {}".format(loc,len(searchValue), hexlify(v)) )
#                        print ("Grabbing value from position {} of length {}: {}".format(loc,len(searchValue), hexlify(v)) )
        # Finished all blocks. If matched at least once, mark it
        logging.debug ("Matching of the last search is: {}".format( matched ) )
#        print ("Matching of the last search is: {}".format( matched ) )

        if matched and len(value)>0:
            if value not in patternMatches:
                patternMatches.append(list(value))
                logging.debug ("Adding new value %s to mask matches", valueToString(value))
            else:
                logging.debug ("Skipping repeated value %s", valueToString(value))
                
            value=[]
            
        if not matchedOnce and matched:
            matchedOnce = True
            
    if markMatches and len(patternMatches)==0: # This means the pattern matched but no value was extracted
        patternMatches.append(matchedOnce)
        logging.debug ("Adding matching value %s to mask matches", matchedOnce)
            
            
# ##           break; # Break here if we need a single value

        
    fdesc.close()
    
    return patternMatches


'''
    Classification section
'''
def getClassValues(model,patternMask,classIndex):

    result=[]
    for f in model[patternMask][1][classIndex]:
        if type(f) is bool:
            r = f
        else:
            r = valueToString (f)
            
        if type(r) is list:
            result.append( ''.join(r) )
        else:
            result.append( r )
            
    return result


def getProbabilityTable (model,doPrint=False):
    """Returns the probability table for a model
    
        Args:
            model (dict): A model
    
        Returns:
            dict: Probability table, keys are pattern masks
    
    """
    ptable={}
    for k in model.keys():
#        ptable[k]=getProbabilityTableForPattern(model,k,doHex=doHex,doJoin=doJoin)
        ptable[k]=getProbabilityTableForPattern(model,k)
        if doPrint:
            print
            print 'Pattern: ' , k
            print ptable[k]
            print
    return ptable


def getProbabilityTableForPattern (model,pmask):
    """Constructs a probability table by calculating frequencies
    
        Args:
            patternCounts (list): List of pattern counts. Each element corresponds to a file type
            
        Returns:
            list: List of frequencies that correspond to each value
            
        The function transforms lists of pattern counts in a list of frequencies. The argument
        contains different lists, first one usually for the clean files, second for the stego files.
        Results are normalized by dividing by the total number of values.
    """
    probs = []
    for fileClass in range(len(model[pmask][1])):
#        vals = getClassValues(model,pmask,fileClass,doHex=doHex,doJoin=doJoin)
        vals = getClassValues(model,pmask,fileClass)
        count = Counter(vals)
        total = float(sum(count.values()))
        freqs={}
        for v,c in count.items():
            freqs[v]=c/total
        probs.append (freqs)

    return probs 

def padjust (f,default=0.01):
    """Utility function that returns a small probability for 0-freq values 
       and also returns the maximum probability if several values are found
    
        Args:
            f (list): List of values
            
        Returns
            double: Maximum value found in the probability table for f
    """
    if len(f)>0:
        return max(f)
    else:
        return default
    
def normalize (l,alpha=0.0,n=1):
    """Utility function that normalizes a list using a Laplace smoothing technique"""
    total = sum(l)+n*alpha
    if total > 0:
        n = list ( (v+alpha)/total for v in l)
    else:
#    print "ERROR: Cannot normalize list: " , l
        vals=len(l)
        n=[1/float(vals)]*vals
#        raise RuntimeError ("normalize() was passed 0 values")
    return n    
    
def classifyFile (model,filename,maxlen=0,defaultValue=0.0001,showInfo=False,useMatchingAsValues=True):
    """Applies the model to obtain the predicted probability distribution for a file
    
        Args:
            model (dict): The model that will be used for classification
            filename (string): The file to be classified
            maxlen (long): Length in bytes of the part of the file that is read
            
        Returns:
            tuple: Likelihood of being clean, probability of being stego

        
        Returns non-normalized values that must be normalized later. Usually it is
        enough to select the larger value as maximum likelihood class.
        
        For fixed pattern matching, the call to getValuesForPattern will return
        True if pattern is present in the file, False if not
    """
    pclean=1.0
    pstego=1.0
    matchedkeys=[]
    ptable=getProbabilityTable(model)
    for k in model.keys():
        if showInfo:
            print ("")
            print ("Classify file: '{}' with pattern: {}".format(filename,k))
            
        probs=getProbabilityTableForPattern(model,k)
        
        vals=getValuesForMask(mask=k,filename=filename,maxlen=maxlen,markMatches=useMatchingAsValues)
        # Here vals is either a list of matches or a single boolean,
        # False if it didn't match, True if it matched
        
        
        if (len(vals)==1) and (type(vals[0]) is bool):
            doHex=False
        else:
            doHex=True
            
        if doHex:
            vals=valuesToHexList (vals)

        if showInfo:
            print ("  Found {} values: {}".format(len(vals),vals))

        if len(vals)>1:
            if showInfo:
                print ("  Found more than one value, ignoring pattern ".format(k))
            pc=1.0
            ps=1.0
        elif len(vals)==1:

#        if len(vals)>0:
            if (vals==[False]):
                if showInfo:
                    print ("  Pattern: {} did not match the file".format(k))
                    
                if len(probs[0].keys())==0: # Table for clean has no value
                    pc = 1.0
                    if len(probs[1].keys())>0: # Table for stego has some values
                        ps = probs[1].values()[0] # TODO: Questionable
                        if showInfo:
                            print '  For pattern: ', k, '  No match, use ps=', ps 
                    else:
                        ps = defaultValue
                elif len(probs[1].keys())==0: # Table for stego has no value
                    ps = 1.0
                    if len(probs[0].keys())>0: # Table for clean has some values
                        pc = probs[0].values()[0] # TODO: Questionable
                        if showInfo:
                            print '  For pattern: ', k, '  No match, use pc=', pc 
                    else:
                        pc = defaultValue
                else: # No grounds to use this attribute
                    pc=1.0
                    ps=1.0

            else:
                    
                if len(probs[0].keys())==0: # Table for clean has no value
                    pc = defaultValue
                    if len(probs[1].keys())>0: # Table for stego has some values
                        ps = probs[1].values()[0] # TODO: Questionable
                    else:
                        ps = defaultValue
    
                if len(probs[1].keys())==0: # Table for stego has no value
                    ps = defaultValue
                    if len(probs[0].keys())>0: # Table for clean has some values
                        pc = probs[0].values()[0] # TODO: Questionable
                    else:
                        pc = defaultValue
                    
                if len(probs[0].keys())==1: # Table for clean has a single value
                    checkC = probs[0].keys()[0]
                    if checkC in vals:
                        pc = probs[0].values()[0]
                        fs=list (f for v,f in probs[1].items() if v in vals)
                        ps=padjust(fs,default=defaultValue)
                    else:
                        pc = defaultValue
                        ps = probs[0].values()[0] # TODO: Questionable, what if we have more than one
                        
                if len(probs[1].keys())==1: # Table for stego has a single value
                    checkS = probs[1].keys()[0]
                    if checkS in vals:
                        fc=list (f for v,f in probs[0].items() if v in vals)
                        pc=padjust(fc,default=defaultValue)
                        ps = probs[1].values()[0]
                    else:
                        pc = probs[1].values()[0] # TODO: Questionable, what if we have more than one
                        ps = defaultValue
                        
                if len(probs[0].keys())>1 and len(probs[1].keys()) >1:
                    fc=list (f for v,f in probs[0].items() if v in vals)
                    fs=list (f for v,f in probs[1].items() if v in vals)
    #                print ("Values found: {}".format(vals))
    #                print ("fc: values for probability are {}".format(fc))
    #                print ("fs: values for probability are {}".format(fs))
                    valsC=len(probs[0].keys())
                    valsS=len(probs[1].keys())
                    if len(fc)==0 and len(fs)==0:
                        fc=[valsC/float(valsC+valsS)]
                        fs=[valsS/float(valsC+valsS)]
    #                print ("fc: corrected values for probability are {}".format(fc))
    #                print ("fs: corrected values for probability are {}".format(fs))
                    pc=padjust(fc,default=defaultValue)
                    ps=padjust(fs,default=defaultValue)
                
            matchedkeys.append((k,pc,ps))

        if (pclean*pc)>0:
            pclean = pclean*pc
        if (pstego*ps)>0:
            pstego = pstego*ps

        if showInfo and len(vals)>0:
#            printProbabilityTableForMask(ptable,k,True)
            print '  For pattern [',k,']: Values: ', vals
            print '  For pattern [',k,']: Clean: ', pc, ' Stego: ', ps
            print '  Total Probs: pclean: ', pclean, ' pstego: ', pstego
            print
            
        if pclean==0 or pstego==0:
            print
            print ' WARNING: We have met a 0 probability, this should not happen '
            print '   Partial probs: pc: ', pc, ' ps: ', pstego
            print '   Total Probs: pclean: ', pclean, ' pstego: ', pstego
            print
#            break    
    
    if showInfo:
        print 'RESULT: Classify file [',filename,']: Clean: ', pclean, ' Stego: ', pstego

    if pclean==0 or pstego==0:
        print 'RESULT: File: ' , filename, ' no match for pattern ', k
    
    return (pclean,pstego),matchedkeys


def doTest (model,fileSet,maxlen=0,alpha=0.0):
    """Classifies a full fileset with a model
    
        Args:
            model (dict): A model
            fileSet (list): A list of pairs (clean,stego) OR
                            A list of single files
        Returns:
            list    Result list, one row per file
            dict    Model keys, number of significative matches, that is, where
                    probability for both classes are different
                    
        Example: 
            fileSet = sa.purgeFileList(sa.readFileList('../../data/ukent2/StegoArchive/OpenPuff MP4/',
                            coverDir='Unmodified',
                            stegoDir='Modified', 
                            extension='mp4'))
            model = pickle.load (open (models_file,'rb') )
            res,significativeMatches,fileStats = doTest(model[fold_index]['model'],fileSet)
    """
    res2=[]
    significativeMatches={}
    fileStats={}
    for k in model:
        significativeMatches[k]=0
    if type(fileSet[0]) is list or type(fileSet[0]) is tuple:
        # We have a list of lists, each element is a fail pair (clean,modified)
        for filepair in fileSet:
            for c in range(len(filepair)):
                res=[]
#                cList = classifyFile (model,filepair[c],maxlen=maxlen,doHex=doHex,doJoin=doJoin)
                cList,matchedKeys = classifyFile (model,filepair[c],maxlen=maxlen)
                for mk in matchedKeys:
                    if not (mk[1]==mk[2]):
                        if mk[0] in significativeMatches:
                            significativeMatches[mk[0]]=significativeMatches[mk[0]]+1
                        else:
                            significativeMatches[mk[0]]=1
#                    else:
#                        print 'Skipping pattern: ', mk[0], ' with mk[1]=', mk[1], ' mk[2]=', mk[2]
                nList = normalize(cList,alpha)
                if nList==None:
                    import pickle
                    print ' Error in normalization, debug info:'
                    print ' File:', filepair[c]
                    print ' Maxlen:', maxlen
                    print ' Saving model to debug_model.p'
                    pickle.dump(model,open('debug_model.p','wb'))
                    pickle.dump(cList,open('debug_clist.p', 'wb'))
                    raise RuntimeError (' CLASSIFICATION ERROR, EXITING PROGRAM')
                res.append(filepair[c])
                res.append(c)
                res += cList
                res += nList
                pred=nList.index(max(nList))
                res.append(pred)
                if (c==pred):
                    res.append('OK')
                else:
                    res.append('NOK')
                
                res2.append(res)
                fileStats[filepair[c]]={ 'class':c, 'predicted':pred , 'patterns': matchedKeys}
    else:
        # We have a list of files with no class
        for file in fileSet:
            res=[]
#            cList = classifyFile (model,file,maxlen=maxlen,doHex=doHex,doJoin=doJoin)
            cList,matchedKeys = classifyFile (model,file,maxlen=maxlen)
            for mk in matchedKeys:
                if not (mk[1]==mk[2]):
                    if mk[0] in significativeMatches:
                        significativeMatches[mk[0]]=significativeMatches[mk[0]]+1
                    else:
                        significativeMatches[mk[0]]=1
            nList = normalize(cList,alpha)
            res.append(file)
            res.append('?')
            res += cList
            res += nList
            pred=nList.index(max(nList))
            res.append(pred)
            res.append('?')
            
            res2.append(res)        
            matchedKeys.append(-1)
            fileStats[file]={ 'class': -1, 'predicted':pred , 'matches': matchedKeys}
            
    return res2,significativeMatches,fileStats

'''
    A series of utility functions for debugging the module
'''
def valueToString (v):
    """Utility function that hexlifies a list """
    return list( hexlify(b) for b in v )

def valuesToHexList (valueList):
    """Utility function that joins the hexlified values of a list """
    return list ( ''.join(valueToString(v)) for v in valueList )

def flattenListOfList(listOfLists):
    return list ([item for sublist in listOfLists for item in sublist])



def checkValuesForMask (filenames,mask,maxlen=0,verbose=True,from_end=False):
    values={}
    if verbose:
        print ('  Mask: %s' % mask)
    for filename in filenames:
        if verbose:
            print ('  File: %s' % filename)
            print ('    Values: %s' % valuesToHexList(getValuesForMask(mask=mask,filename=filename,maxlen=maxlen,from_end=from_end)))
        values[filename]=valuesToHexList(getValuesForMask(mask=mask,filename=filename,maxlen=maxlen))
    return values

def generalizeMaskList (maskList,skipChar='*',chunk=2):
    '''generalizeMaskList
        Returns the intersection of all masks up to the minimum length
        Elements that are not equal are replaced by the skipChar
    '''
    result=''
    mlen= min ( len(m) for m in maskList)
    for i in range(mlen)[::chunk]:
        v= set(m[i:i+chunk] for m in maskList)
        if len(v)==1:
            result+=v.pop()
        else:
            result+=skipChar*chunk
    return result

def printProbabilityTableForMask (ptable,mask,inColumns=False,maxLines=10):
    """Prints the probability table for a model
    
        Args:
            ptable (dict): A probability table, indexed by mask
    
    """
    if inColumns:
        print '    Class: ' ,   0, '\t\t Class ', 1
        print '  -----------' , ' \t\t--------- '
        l0=len(ptable[mask][0].keys())
        l1=len(ptable[mask][1].keys())
        indexes=max(l0,l1)
        for i in range(indexes):
            if (i < l0):
                v0=ptable[mask][0].keys()[i]
                print '   ', v0,':',round(ptable[mask][0][v0],2),
            if (i < l1):
                v1=ptable[mask][1].keys()[i]
                if (i>=l0):
                    tabn='\t\t\t'
                else:
                    tabn='\t'
                print tabn, ' ', v1,':',round(ptable[mask][1][v1],2)
    else:
        for c in range(len(ptable[mask])):
            print '  Class: ' , c
            ind = 0
            for val,prob in ptable[mask][c].items():
                if maxLines==0 or ind<maxLines:
                    print val,':',prob
                if maxLines>0 and ind==maxLines:
                    print '...'
                ind+=1
                    

def getKey(aList,indexNo=0):
    return aList[indexNo]


def printProbabilityTable (ptable,inColumns=False):
    """Prints the probability table for a model
    
        Args:
            ptable (dict): A probability table, indexed by mask
            masks (list): A list of masks to filter the output
    
    """
    for k in ptable.keys():
        print
        print 'Pattern: ' , k
        printProbabilityTableForMask(ptable,k,inColumns)
        
def getContingencyTable (fileset,masks,maxlen):
#    print '  & Values(Clean) & Values(Modified) \\\\'
    lines=[]
    for mask in masks:
#        print getMaskFromPattern(pat),' &  &  \\\\'
        for filepair in sorted(fileset,key=getKey):
            line=[mask]
            filename = os.path.basename(filepair[0])
            line.append(filename)
#            print filename, '&',  
            v=(valuesToHexList(getValuesForMask(filename=filepair[0],
                                                      mask=mask,maxlen=maxlen)),
              valuesToHexList(getValuesForMask(filename=filepair[1],
                                                      mask=mask,maxlen=maxlen)))
            line.append (v[0])
            line.append (v[1])
            lines.append(line)
    return lines

def getMaskList (maskDict):
    maskList=[]
    for k,v in maskDict.items():
        maskList += v
    return maskList

def getMaskSet (maskDict):
    return set(getMaskList(maskDict))

