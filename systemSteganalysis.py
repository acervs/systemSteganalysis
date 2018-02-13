# -*- coding: utf-8 -*-


# System Analysis
# ===============
#
# :Script:    systemSteganalysis.py
# :Date:      January 31st, 2018
# :Revision:  1.2
# :Copyright: © 2016-2018: Alejandro Cervantes <acervant@inf.uc3m.es>
from __future__ import print_function


""" systemSteganalysis

   This module performs system analysis for a set of files. 
   Basic method is to scan the training file pairs (clean,stego)
   searching for patterns that are later used to construct a model for
   classification of arbitrary files in one of the aforementioned classes
   
   This module extracts patterns for Flag Replacement from the beginning of the file
   and patterns for EOF Injection from the start of the injected code
   
"""

import logging
from datetime import datetime
import os

from optparse import OptionParser
import pickle
import numpy as np

import sys
import os.path
import cluster
import csv
from binascii import  hexlify,unhexlify



# Functions related to the pattern type
from systemAnalysisUtils import getMaskFromPattern,getPatternFromConstantMask

# Functions related to file access
from systemAnalysisUtils import getEOF,readFileList,searchFile

# Functions related to pattern collection
from systemAnalysisUtils import collectPatternsEOFInjection,collectPatternsMethod1,collectPatternsMethod5

# Functions related to model construction
from models import buildRawModelFromMasks,getProbabilityTable,getValuesForMask,getSuperMasks
from models import doTest,printProbabilityTable,getMaskList,generalizeMaskList

'''
    maskMatches,excludeHorizontalClusters,getGeneralizedMasks
    
    These functions have to do with pattern generalization and should be moved
    to a separate module
'''
def maskMatches (generalizedMask,normalMask,skipChar='*'):
    matches=True
    if len(generalizedMask)==len(normalMask):
        for i in range(len(generalizedMask)):
            if generalizedMask[i]!=skipChar and generalizedMask[i]!=normalMask[i]:
                matches=False
                break;
    else:
        matches=False
        
    return matches

def excludeHorizontalClusters(masks,generalizedMasks):
    filteredClusters=[]
    for gm in generalizedMasks:
        if ('?' in gm):
            for k,v in masks.items():
                numFounds=sum (1 for p in v if maskMatches(gm,p))
                if numFounds>1:
                    break; # We are exluding this cluster
                
            if numFounds<=1:
                filteredClusters.append(gm)
        else:
            filteredClusters.append(gm)
        
    return filteredClusters

def getGeneralizedMasks(clusteredMasks):
    # Now generate the generalized mask that corresponds to each cluster
    generalizedMasks=[]
    for m in clusteredMasks:
        generalizedMasks.append (generalizeMaskList(m))

    return generalizedMasks

def searchGeneralizedMaskInFiles(mask,files,maxlen=0,from_end=False):
    fileVals=[]
    for f in files:
        v=[f]
        vals = getValuesForMask(mask,f,from_end=from_end,markMatches=True)
        v+= vals
        print ("{}:{}".format(f,vals))
        fileVals.append(v)
    return fileVals


def searchSignaturePosition (mask,filePairs,relative=True,maxlen=0):
    '''searchSignaturePosition
    
        Explores a set of files and retrieves the position of a given signature
        For signatures found after the end of the clean parte, use relative = True
        Returns a list of files, with the attribute True/False and the position of the first match
    '''
    pattern=getPatternFromConstantMask(mask)
    searchSig=[]
    for clean,stego in filePairs:
        eof=getEOF(clean)
        match,pos = searchFile(clean,pattern,maxlen=maxlen)
        searchSig.append([clean,match,pos])
        match,pos = searchFile(stego,pattern,maxlen=maxlen)
        if relative:
            pos = pos - eof
        searchSig.append([stego,match,pos])
    return searchSig

def loadFiles():
    '''loadFiles
        Loads the current data sets
    '''
    files={}
    files["OpenPuff FLV"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OpenPuff FLV',
        coverDir='Clean',stegoDir='Modified', extension='flv'))
    files["OpenPuff MP4"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OpenPuff MP4',
        coverDir='Clean',stegoDir='Modified', extension='mp4'))
    files["OpenPuff MPEG"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OpenPuff MPEG',
        coverDir='Clean',stegoDir='Modified', extension='mpg'))
    files["F5 JPEG"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/F5 JPEG',
        coverDir='Clean',stegoDir='Modified', extension='jpg'))
    files["OpenPuff MP3"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OpenPuff MP3',
        coverDir='Clean',stegoDir='Modified', extension='mp3'))
    files["OmniHide Pro MP4"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OmniHide Pro MP4',
        coverDir='Clean',stegoDir='Modified', stegoSuffix='_Out', extension='mp4'))
    files["Masker AVI"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/Masker',
        coverDir='Clean',stegoDir='Modified', extension='avi'))
    files["DeepSound WAV"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/DeepSound WAV',
        coverDir='Clean',stegoDir='Modified', extension='wav'))
    files["PixelKnot JPG"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/PixelKnot',
        coverDir='Clean',stegoDir='Modified', extension='jpg'))
    files["OpenPuff WAV"]=purgeFileList(readFileList('../../data/ukent2/StegoArchive/OpenPuff WAV',
        coverDir='Clean',stegoDir='Modified', extension='wav'))
    return files

def purgeFileList (fileList):
    '''purgeFileList
        Removes a file from a list if we can't find both objects in the file system
    '''
    fileList2 = list ( (c,s) for c,s in fileList if os.path.isfile(c) and os.path.isfile(s))
    return fileList2



def splitFolds(fileList,folds=10,useSeed=None):
    '''
        Splits a list of files in train and test indexes
        Returns a randomized file list and a list of boolean arrays where
        True: data shall be used for training
        False: data shall be used for testing
    '''
    if not useSeed is None:
        np.random.seed(useSeed)
    rndlist = np.array(fileList)
    np.random.shuffle(rndlist)
    totalFiles=len(rndlist)
    foldLength=int(totalFiles/folds)
    trainSets = []
    # Test files are marked as False, train are marked as true
    for foldNumber in range(folds):
        train_inds = np.ones(totalFiles,dtype=bool)
        train_inds[foldNumber*foldLength:(foldNumber+1)*foldLength]=False
        trainSets.append(train_inds)
        
    return rndlist,trainSets

def saveData(myfile,data,mode='wb'):
    '''saveData
        Writes data in csv format
    '''
    with open (myfile,mode) as outfile:
        writer = csv.writer(outfile)
        writer.writerows(data)
        
def getPatternStats (mask,fileStats):
    '''getPatternStats
        Extracts from a fileStats structure the information regarding a single pattern
        This is used to decide the match count and success percentage per pattern
    '''
    results={}
    for f,v  in fileStats.items():
        for pl in v['patterns']:
            if pl[0]==mask:
#                if not mask in results.keys():
#                    results[mask]={}
                if pl[2]>=pl[1]:
                    predicted = 1
                else:
                    predicted = 0
                if v['predicted']==predicted:
                    result='OK'
                else:
                    result='NOK'
                results[f]=pl[1],pl[2],v['class'],v['predicted'],result
    return results

def sumResults (results):
    '''sumResults
        Gets the total success rate for a result structure
        Assumes the final field is OK for success and NOK if not
    '''
    g=0
    b=0
    res = -1
    for r in results.values():
        if r[-1]=='OK':
            g=g+1
        else:
            if r[-1]=='NOK':
                b=b+1
    if (g+b)>0:
        res = g / float(g+b)
    return res

def getBestPatterns (model,files,maxlen=0):
    '''getBestPatterns
        Trains with model and generates stats
    '''
    results,matches,fileStats = doTest(model,files,maxlen=maxlen)
    return results,matches,fileStats

def printBestPatterns (results,matches,fileStats,threshold=1.0):
    '''printBestPatterns
        Generates the rows of LaTEX tables with pattern stats
    '''
    thnum = int (len(fileStats.keys()) * threshold)
    bestpats = list ( p for p,v in matches.items() if v >= thnum)
    for p in bestpats:
        pStats=getPatternStats(p,fileStats)
        print ("{} & {} & {}".format(p ,matches[p],sumResults(pStats)))

def printFailures(results,skipCharsInName=45):
    fails = list ('{},{},{}'.format(i[0][skipCharsInName:],i[2],i[3]) for i in results if i[-1]=='NOK')
    for i in fails:
        print (i)

def refineModel (model,tsize,type=3,minVals=10):
    '''
        Basic refining
        - Always: Delete void patterns
        - Always: Delete patterns whose probability table is equal
        
        Depending on type:
        - Minimal(3): Delete patterns whose values seem random
        - Medium(2): Keep only patterns that were found in either all the training OR all the testing files
        - Aggressive(1): Do not use. Keep only patterns found in both all training AND testing files.
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

def mergePatternLists (oldPatterns,newPatterns):
    '''mergePatternLists
        Adds newPatterns to the lists in oldPatterns, avoiding duplicates
        Both oldPatterns or newPatterns are dictionaries whose keys are the files
        where the patterns are extracted from
    '''

    for k,v in newPatterns.items():
        if k in oldPatterns.keys():
            oldMasks = ( getMaskFromPattern(p) for p in oldPatterns[k])
            for p in v: # Patterns extracted from a file
                pmask = getMaskFromPattern(p)
                if not pmask in oldMasks:
                    oldPatterns[k].extend(v)
        else:
            oldPatterns[k]=v
            
    return oldPatterns





def getMaskDict (patternDict):
    maskDict = {}
    for k,v in patternDict.items():
        mlist = list (getMaskFromPattern(p) for p in v)
        maskDict[k]=mlist
    return maskDict
        
def getLimits (limits,key,defaultMin=2,defaultMax=2):
    '''Access the limit structure and get the value of a key
    '''
    if key in limits.keys():
        minLimit=limits[key][0]
        maxLimit=limits[key][1]
    else:
        minLimit=defaultMin
        maxLimit=defaultMax
    return minLimit,maxLimit

def countValues (aDictionary):
    count = sum (len(v) for k,v in aDictionary.items())
    return count

def explorePatterns (trainSet,maxlen,verbose=False,
                     limits={ 'head': (0,5) , 'tail': (0,5), 'var': (0,6)},
                     methods=['START'],
                     **kwargs):
    '''explorePatterns
        
        Finds patterns in the train set using the specified methods and parameters.
        
        TODO:
        The parameter "fromStartOfDifferences" is used in OpenPuff WAV to ensure we are searching
        starting with the first position where a change is detected. This is only required because
        those files have a significant part of the start of the file that is identical in both
        files. This method can be generalized to all the experiments (but hasn't yet)
        
        Arguments:
            trainSet (list): Contains a list of pairs of files (cover,stego)
            maxlen (long): Maximum length to be explored
            methods (list): List of available methods for pattern extraction. Currently 'START'
                searches the start of the file, 'END' searches the end, and 'EOF'
                searches beyond the EOF of the shortest file
                
    '''
    patterns={}
    minhead,maxhead = getLimits (limits,'head')
    mintail,maxtail = getLimits (limits,'tail')
    minvar,maxvar = getLimits (limits,'var')
    
    tsize=int(len(trainSet))
    logging.warning ("For training we are using %s files", tsize)
    
        
    
    for hl in range (minhead,maxhead+1):
        for tl in range (mintail,maxtail+1):
            for vl in range (minvar,maxvar+1):
                # Collection from the start of file
                if 'START' in methods:
                    logging.info ("      Collecting from START of file patterns for head,tail,var=(%s,%s,%s)",hl,tl,vl )
                    newPatterns=collectPatternsMethod1(trainSet,maxlen=maxlen,varlen=vl,headlen=hl,taillen=tl,fromStartOfDifferences=False)
                    patterns = mergePatternLists (patterns,newPatterns)
#                patterns = mergeSuperPatternLists (patterns,newPatterns)                 
                
                # Collection from the end of file
                if 'END' in methods:
                    logging.info ("      Collecting from END of file patterns for head,tail,var=(%s,%s,%s)",hl,tl,vl )
                    newPatterns=collectPatternsMethod5(trainSet,maxlen=maxlen,varlen=vl,headlen=hl,taillen=tl)
                    patterns = mergePatternLists (patterns,newPatterns)                    
#                patterns = mergeSuperPatternLists (patterns,newPatterns)                    
                        
        if 'EOF' in methods:
            logging.info ("      Collecting patterns for EOF injection with total length=%s",hl+hl )
            newPatterns,pmasks = collectPatternsEOFInjection (trainSet[0:tsize],maxlen=maxlen,headlen=hl,taillen=hl)
            npats = sum (len(k) for k in (plist for k,plist in newPatterns.items()))
            logging.info ("      Patterns collected by EOF Injection: %s",npats)

        patterns = mergePatternLists (patterns,newPatterns)                    

        
    return patterns 

def doExperimentWithTest (trainWith,
                          evaluateWith,
                          outFile='experimentResult.csv',
                          maxlen=1024,
                          trainNumber=0,
                          successThreshold=1.0,
                          limits={ 'head': (0,5) , 'tail': (0,5), 'var': (0,6)},
                          generalizeMasks=False,
                          methods=['START'],
                          **kwargs):
    
    '''doExperimentWithTest
        This experiment searches for the best model using the test set for guidance
        It requires testfiles!=None
        
        Current implementation builds the model only with patterns that were found at
        least in two training files. This includes patterns generalized using
        the clustering mechanism. 
        
        If only the generalized masks are used we are filtering out every pattern
        only present in a single file. However that situation precludes our grabbing
        a pattern from the start of a file that is present in a different section
        in the rest of the files. We should use longer blocks in this case for pattern
        search.
        
        Arguments:
            trainWith (list): Contains a list of pairs of files for training
            evaluateWith (list): Contains a list of pairs of files for evaluation
            outFile (string): Exports results to this file
            maxlen (long): Explore this amount of data when extracting patterns
            trainNumber (int): Use this number of train files even if the trainfiles list is longer
            kwargs (dict): Arguments that will be passed over
    '''
    
            
    
    assert not (evaluateWith is None)
    
    logging.info ("doExperimentWithTest: Collecting patterns, exploring section of %s bytes for each type", maxlen)
    if trainNumber>0:
        trainSet=trainWith[0:trainNumber]
    else:
        trainSet=trainWith
        
    logging.info ("doExperimentWithTest: Total train set length: %s", len(trainWith))
    logging.info ("doExperimentWithTest: Using as train set length: %s", len(trainSet))
    

    # We start with fixed limits whose value is the maximum for the range
    headLimit =(limits['head'][1],limits['head'][1])    
    tailLimit =(limits['tail'][1],limits['tail'][1])

    # We always explore different lengths for the variable part
    varLimit  =(limits['var'][0],limits['var'][1])    
    
    finishExperiment=False
#    patterns={}
    
    while not finishExperiment and headLimit[0]>=limits['head'][0] and tailLimit[0]>=limits['tail'][0]: # Exit when conditions met
        # Discard patterns found by previous iteration
        patterns={}
        
        currentLimits= { 'head': headLimit , 'tail': tailLimit, 'var': varLimit}
        logging.info ("doExperimentWithTest: Exploring patterns, searching %s bytes", maxlen)
        logging.info ("doExperimentWithTest: Pattern sizes inside limits: %s", currentLimits)
        
        newPatterns=explorePatterns(trainSet,maxlen,limits=currentLimits,methods=methods,**kwargs)
        
        npats = sum (len(k) for k in (plist for k,plist in newPatterns.items()))
        logging.info ("doExperimentWithTest: Extracted patterns:  %s, use only these for model building", npats)
        
        patterns = mergePatternLists (patterns,newPatterns)
#        patterns = mergeSuperPatternLists (patterns,newPatterns)

        results=None    
        model=None    
        modelR=None
        matches=None
    
        if npats>0:
            modelMaxLen=0
            
            # We transform the patterns in masks
            maskDict = getMaskDict(patterns)

            # Concatenate the lists found in all files
            maskList = getMaskList(maskDict)
#            for m in maskList:
#                logging.info ("doExperimentWithTest: Extracted pattern: %s", m)
                
            # Keep only non-repeated masks and masks not included in others
            # This means that some of the shorter masks will never be used for attribute extraction
            # in the model, in the assumption that the training data is general enough
            '''
            patternList = getSuperMasks([],patterns)
            maskDict=getMaskDict(patterns)
            maskList=getMaskList(patternList)
            for m in maskList:
                logging.info ("doExperimentWithTest: Keeping only super patterns: %s", m)
            '''   

            # Mask generalization is switched from the command line
            # Generalization is only made over the supermasks
            # The resulting generalized masks are inserted into the original dictionary of masks
            if generalizeMasks:
                clusterThreshold=0.2
                clusterMinSize=2
                                
                logging.info ("doExperimentWithTest: Clustering patterns, threshold %s, minimum of %s matches",clusterThreshold,clusterMinSize)
                if len(maskList)>0:
                    Z,data,ca,uniqueMasks = cluster.hierarchicalCluster2({'all':maskList},useUnique=False)
                    clusteredMasks= cluster.clusterList(Z,data,clusterThreshold,clusterMinSize)
                    generalizedMasks = getGeneralizedMasks(clusteredMasks)
                    filteredMasks = excludeHorizontalClusters(masks=maskDict,generalizedMasks=generalizedMasks)
                    
                maskDict['generalizedMasks']=filteredMasks
                logging.info ("doExperimentWithTest: Generalizing patterns, generated %s patterns",len(filteredMasks))
                
                logging.info ("doExperimentWithTest: CONFIGURATION Using ONLY generalized patterns")
                logging.info ("doExperimentWithTest: Note that this may exclude useful patterns in some cases")
 
               
                modelMasks={'generalizedMasks':filteredMasks}
#                for m in modelMasks['generalizedMasks']:
#                    logging.info ("doExperimentWithTest: Generalized Pattern in model: %s", m)
                    
                
            else:
                # modelMasks=masks
                logging.info ("doExperimentWithTest: CONFIGURATION Using basic (non generalized) patterns")
#                modelMasks={'generalizedMasks':maskList}
                modelMasks=maskDict
                
            
            logging.info ("doExperimentWithTest: CONFIGURATION Excluding multiple-valued matches in classification")

            
            numberOfMasks = sum (len(k) for k in (plist for k,plist in modelMasks.items()))
            logging.info ("doExperimentWithTest: Building model, searching %s patterns, checking %s bytes per file (0: full file)",numberOfMasks,modelMaxLen)
            model=buildRawModelFromMasks(maskSet=modelMasks, fileSet=trainSet,maxlen=modelMaxLen)

            logging.info ("doExperimentWithTest: Raw model has %s unique patterns", len(model.keys()))

            if len(model.keys())>0:
                tsize=len(trainSet)

                logging.info ("doExperimentWithTest: Refining model")
                modelR = refineModel (model,tsize)

                    
                if len(modelR.keys())>0:
                    logging.info ("doExperimentWithTest: Refined model has %s patterns", len(modelR.keys()))
                    logging.info ("doExperimentWithTest: Testing model")
                    results,matches,fileStats=doTest(modelR,evaluateWith,maxlen=modelMaxLen)
                                       
                    goodRes = sum (1 for r in results if r[-1]=='OK')
                    badRes = sum (1 for r in results if r[-1]=='NOK')
                    if (goodRes+badRes)>=0:
                        success = goodRes / float(goodRes + badRes)
                        logging.info ("doExperimentWithTest: Achieved success of %s (threshold=%s)", success, successThreshold)
                        if success >= successThreshold:
                            finishExperiment=True

#                    modelSuperMasks = getSuperMasks(modelR.keys())
#                    modelNonRed = { m:v for m,v in modelR.items() if m in modelSuperMasks}
                    
#                    logging.info ("doExperimentWithTest: Refined model has %s NON REDUNDANT patterns", len(modelNonRed.keys()))
#                    results,matches,fileStats=doTest(modelNonRed,evaluateWith,maxlen=modelMaxLen)
                    

                
                else:
                    logging.info ("doExperimentWithTest: Refined model was empty")
            else:
                logging.info ("doExperimentWithTest: Refined model was empty")
        else:
            logging.info ("doExperimentWithTest: Extracted no patterns with current configuration")
                    

        # Next iteration: we decrement both values in 1 unit
        if (headLimit[0] > tailLimit[0]):
            headLimit =(headLimit[0]-1,headLimit[1]-1)
            tailLimit =(tailLimit[0],tailLimit[1])
        else:
            headLimit =(headLimit[0],headLimit[1])
            tailLimit =(tailLimit[0]-1,tailLimit[1]-1)

    return results,modelR,model,patterns,matches

def doExperimentSimple (trainWith,evaluateWith,models=None,
                        outFile='experimentXValResult.csv',maxlen=1024,trainNumber=0,
                        doTrain=False,successThreshold=0.0,verbose=False,oneIteration=True,
                        methods=['START'],
                        **kwargs):
    '''
        Performs a single-pass experiment, generating the model with trainset and testing with evaluateWith,
        which is defined as a test set different from the final validation set in cross-validation.
        If an evaluation set is provided, and the expected success rate is not reached,
        then the experiment is repeated with a higher maxlen value.
        
        Args:
            trainWith (list): List of pairs of files used for training
            evaluateWith (list): Either list of pairs or list of files, used for evaluation
            models (list): List of models for testing, only used if no training is required (doTrain=False)
            outFile (string): File for output of the results
            maxlen (long): Maximum length for pattern extraction
            trainNumber (int): Maximum number of files for training (rest are not used)
            doTrain (bool): Generate model(s) (requires trainset)
            successThreshold (float): Iterate model generation until threshold is reached on testing (requires testset)
            verbose (bool): Display information on standard output
            oneIteration (bool): Perform just one iteration of the call, do not increase length
            
        Returns:
            totalResults (list): A list of results, one per each model tested
            models (list): A list of models, one per iteration until reaching the threshold

        Example: To generate a model for some files, improving the successThreshold use this
        
            totalResults,models = do.doExperimentSimple (trainWith=maskerFiles[0:25],evaluateWith=maskerFiles[25:],
                models=None,outFile='exp_simple_train_test_Masker.csv',
                maxlen=1024*8,,doTrain=True,successThreshold=0.95)

        Example: To validate all of the above models, (see that we use maxlen=0)
        
            totalResults,m = do.doExperimentSimple (trainWith=None,evaluateWith=validationFiles],
                models=models,outFile='exp_simple_validation_Masker.csv',
                maxlen=0,doTrain=False)

    '''
    totalResults=[]
    modelStructs=[]

    
    if doTrain:
        logging.info("doExperimentSimple: Training up to success rate of %s", successThreshold)
        runExp=True
        if not oneIteration and evaluateWith:
            currentMax=1024
        else:
            # Single-pass training
            currentMax=maxlen
            
        modelStructs=[]
        while runExp and currentMax<=maxlen:
            logging.info ("doExperimentSimple: Run experiment with currentMax: %s", currentMax)
            modelR={}
            trainOnly=max(len(trainWith),trainNumber)
            results,modelR,model,patterns,matches = doExperimentWithTest(
                                                          trainWith=trainWith,
                                                          evaluateWith=evaluateWith,
                                                          maxlen=currentMax,
                                                          trainNumber=trainNumber,
                                                          successThreshold=successThreshold,
                                                          methods=methods,
                                                          **kwargs)
                
            
            evaluationResults = { 'successRate': None }
            if evaluateWith:
                successRate=0.0
                if results:
                    successRate = sum (1 for l in results if l[-1]=='OK' ) / float(len(results))
                    logging.info ("doExperimentSimple: Experiment finished with testing result of: %s", successRate)
                    totalResults.append(results)
                    if successRate >=successThreshold:
                        runExp=False
                        logging.info ("doExperimentSimple: Reached threshold of: %s, experiment finished", successThreshold)
                else:
                    logging.info ("doExperimentSimple: Not reached threshold of: %s, increasing maxlen to:", currentMax)
                currentMax+=1024
                evaluationResults['successRate']=successRate
            else:
                # Single-pass training (not needed as we already set maxlen)
                runExp=False
                
            parameters = { 'maxlen':currentMax, 'trainfiles': list(trainWith[0:trainOnly]), 'testfiles': list(evaluateWith), 'trainNumber':trainOnly}
            modelStructs.append( { 'parameters': parameters, 'results': evaluationResults, 'rawModel':model, 'model': modelR, 'patterns': patterns} )
            
    else:
        logging.info("doExperimentSimple: Testing a model on a set of files")
        logging.info("doExperimentSimple: Note that test is always over the whole file")
        if 'model' in models[0].keys(): # Models as structures
            modelStructs=models
        else: # Plain models
            logging.debug("Using a plain model for input (no metadata included)")
            for m in models:
                modelStructs.append ({ 'model':m, 'results':-1.0 })
        
        for mS in modelStructs:
#            print 'Model Parameters:', list( '='.join([k,v]) for k,v in mS['parameters'].items() if not k == 'testfiles' and not k=='trainfiles')
            probs = getProbabilityTable(mS['model'])
            if verbose:
                logging.info("Model probability table (output to console)")
                printProbabilityTable(probs,inColumns=True) 
                if mS['results']:
                    logging.info("Test Results for model in training phase were: %s", mS['results'])
                
            actualMaxLen=0
            
            results,matches,fileStats=doTest(mS['model'],evaluateWith,maxlen=actualMaxLen)
            
            if len(results)>0:
                oks = sum (1 for l in results if l[-1]=='OK' )
                noks = sum (1 for l in results if l[-1]=='NOK' )
                if verbose:
                    if (oks+noks)>0:
                        logging.info("doExperimentSimple: evaluation result is %s", oks / float( len(results) ) )
                    else:
                        logging.info("doExperimentSimple: results will be dumped to file")
                totalResults.append(results)

    if outFile:   
        for fold in range(len(totalResults)):
            lines=[]
            for fileresult in totalResults[fold]:
                lines.append([fold]+fileresult)
            if fold==0:
                saveData(outFile,lines,mode='w')
            else:
                saveData(outFile,lines,mode='a')
            
    return totalResults,modelStructs,matches
           
def doExperimentXval(allfiles,outFile='experimentXValResult.csv',modelFile=None,maxlen=0,
                     trainNumber=0,folds=10,methods=['START'],**kwargs):
    '''doExperimentXval
    
        Splits the training data in a number of folds and performs cross validation, calling
        doExperimentSimple first to generate a model, then to try the model in the validation fold
        
        Arguments:
            allfiles (list): List of file pairs to be used for the experiment
            outFile (string): Output csv file with the results of the experiment
            maxlen (long): Number of bytes to be scanned for pattern extraction
            methods (list): Type of patterns to be extracted. This is a list of strings that defaults to the methods implemented
            trainNumber (int): Maximum number of files used for training, can be used for fast training
            folds (int): Number of folds to split the file set into
            
        Returns:
            list: List of result strings for each file
            models: List of models generated (one per fold)
            
    '''
    if 'randomSeed' in kwargs.keys():
        useSeed = int(kwargs.pop('randomSeed'))
    else:
        useSeed = None
    rndList,trainSets=splitFolds(allfiles,folds=folds,useSeed=useSeed)
    foldNumber=0
    if 'foldsToRun' in kwargs.keys():
        if kwargs['foldsToRun'] is None:
            kwargs.pop('foldsToRun')
        else:
            trainSets = list (trainSets[int(i)] for i in kwargs.pop('foldsToRun') )

    if 'successThreshold' in kwargs.keys():
        successThreshold = float(kwargs.pop('successThreshold'))
        logging.info ("doExperimentXval: Setting successThreshold by parameter to: %s" , successThreshold)
    else:
        logging.info ("doExperimentXval: Setting successThreshold by default to: %s" , 0.0)
        successThreshold = 0.0
    
    totalResults=[]
    models=[]
    
           
    for tSet in trainSets:
        logging.info ("doExperimentXval: Fold: %s" , foldNumber)
        trainset = rndList[tSet].tolist()
#        testset = list( f for f in rndList.tolist() if not (f in trainset) )
        validationset = list( f for f in rndList.tolist() if not (f in trainset) )

        # Execute the experiment in order to generate a model. Use half of the files
        # for training, and half for testing
        tlen = len(trainset)/2
        logging.info ("doExperimentXval: Train set length: %s" , len(trainset))
        logging.info ("doExperimentXval: Maximum used for training : %s (0:all files)" , trainNumber)
        logging.info ("doExperimentXval: Test set length: %s" , tlen)
        logging.info ("doExperimentXval: Validation set length: %s" , len(validationset))
        resultsTrain,modelStructs,matches = doExperimentSimple(
                                                       trainWith=trainset[0:tlen],
                                                       evaluateWith=trainset[tlen:],
                                                       models=None, outFile=None,
                                                       maxlen=maxlen,
                                                       trainNumber=trainNumber,
                                                       doTrain=True,
                                                       successThreshold=successThreshold,
                                                       oneIteration=True,
                                                       methods=methods,
                                                       **kwargs)
        
        # Test with the last model retrieved in the previous call
        results,m,matches = doExperimentSimple(trainWith=None,
                                            evaluateWith=validationset,
                                            models=[modelStructs[-1]],
                                            outFile=None,
                                            maxlen=0,
                                            trainNumber=tlen,
                                            methods=methods,
                                            doTrain=False)

        # Add the information about the validation set
        modelStructs[-1]['parameters']['validationfiles'] = list(validationset)
        
        oks = sum (1 for l in resultsTrain[-1] if l[-1]=='OK' )
        logging.info ("Fold: %s, result on test files" , ( foldNumber, oks / float(len(resultsTrain[-1])) ) ) 
        oks = sum (1 for l in results[-1] if l[-1]=='OK' )
        logging.info ("Fold: %s, result on validation files" , ( foldNumber, oks / float( len(results[-1])) ) )
        
        totalResults.append(results[-1])
        models.append(modelStructs[-1])

        logging.info ("Fold: %s, saving results to %s", foldNumber, outFile)
        lines=[]
        for fileresult in results[-1]:
            lines.append([foldNumber]+fileresult)
        if foldNumber==0:
            saveData(outFile,lines,mode='w')
            if not modelFile is None:
                pickle.dump (modelStructs[-1], open (modelFile,'wb'))
        else:
            saveData(outFile,lines,mode='a')
            if not modelFile is None:
                pickle.dump (modelStructs[-1], open (modelFile,'ab'))
        foldNumber+=1
        
    return totalResults,models




def main():
    '''
      Main program
      
      Options:
        cleanDir (string): Use these files as clean train files
        modifiedDir (string): Use these files as modified train files
        maxlen (long): Train using this value as maximum scanning length
        folds (int): Use this number of folds for training. If folds = 1, train with all
                    If folds=0, no train (used for testing)
        dumpFile (string): Dump models to this file
        inputModel (list): List of models for testing
        testDir (string): Test model(s) on these files
        ... and many others (yet to be documented)
    '''

    # Argument Parsing
    # ----------------
    parser = OptionParser()
    parser.add_option("-a", "--analyseModel", help="Use this file to dump the stats about model testing.",
          dest="dumpMatchesFile", default='./doStego_dump_matches.p' )
    parser.add_option("-b", "--baseDir", help="Use this folder as root for the rest of the paths.",
          dest="baseDir", default='./' )
    parser.add_option("-c", "--cleanDir", help="Read files in this folder as clean files.",
          dest="cleanDir", default='./' )
    parser.add_option("-C", "--cleanSuffix", help="Add this to the filename of clean files",
          dest="cleanSuffix", default='' )
    parser.add_option("-d", "--dumpFile", help="Use this file to dump the execution information.",
          dest="dumpFile", default='./doStego_dump.p' )
    parser.add_option("-D", "--debugLevel", help="Use this debug level for logging.",
          dest="debugLevel", default=logging.INFO )
    parser.add_option("-e", "--searchEOF", help="Use if EOF search is required (costly).",
          dest="searchEOF", default=0 )
    parser.add_option("-f", "--folds", help="Use this number of folds for cross validation.",
          dest="folds", default=10)
    parser.add_option("-F", "--foldList", help="Perform the experiment only for this list of folds (use to continue interrupted experiment)",
          dest="foldList", default=None)
    parser.add_option("-g", "--generalize", help="Generalize masks and use only those.",
          dest="generalizeMasks", default=0)
    parser.add_option("-i", "--inputModels", help="Use this model or models for testing.",
          dest="inputModels", default=10)
    parser.add_option("-l", "--maxlen", help="Check this number of bits of every file.",
          dest="maxlen", default=1024 )
    parser.add_option("-L", "--logFile", help="Output information to this log file",
          dest="logFile", default="systemSteganalysis.log" )
    parser.add_option("-m", "--modifiedDir", help="Read files in this folder as modified files",
          dest="modifiedDir", default='./' )
    parser.add_option("-M", "--modifiedSuffix", help="Add this to the filename of modified files",
          dest="modifiedSuffix", default='' )
    parser.add_option("-n", "--maxfiles", help="If non-zero, use this number of train files",
          dest="maxFiles", default=0 )
    parser.add_option("-o", "--outputFile", help="Use this file to output results.",
          dest="outFile", default='./doStego.csv' )
    parser.add_option("-s", "--successThreshold", help="Retrain until success threshold is obtained on the test set",
          dest="successThreshold", default=0.0 )
    parser.add_option("-t", "--testDir", help="Test model with these files",
          dest="testDir", default=None )
    parser.add_option("-x", "--fileExt", help="File extension.",
          dest="fileExt", default="flv" )
    parser.add_option("-z", "--collectParams", help="Limits for pattern collection",
          dest="collectParams", default='0,5,0,5,0,6' )

    (opt,args) = parser.parse_args()
    
    # Set the log level, default is INFO
    logging.basicConfig(filename=opt.logFile,level=opt.debugLevel,filemode='w')

    collectionParams = map (int,opt.collectParams.split(','))
    if len(collectionParams)<6:
        raise RuntimeError("ERROR: Invalid format for collectParams (-z) argument:", opt.collectParams, ' expecting six comma-separated integer values')
    limits = { 'head': (collectionParams[0],collectionParams[1]),
               'tail': (collectionParams[2],collectionParams[3]),
               'var':  (collectionParams[4],collectionParams[5]) }
        
    allfiles=readFileList(baseDir=opt.baseDir,coverDir=opt.cleanDir,
        stegoDir=opt.modifiedDir,coverSuffix=opt.cleanSuffix,stegoSuffix=opt.modifiedSuffix,extension=opt.fileExt)
    allfiles=purgeFileList(allfiles)

    logging.info ("main: Total number of files available: %s" , len(allfiles))
    logging.info ("main: Maximum used for training : %s (0:all files)" , opt.maxFiles)

    if opt.testDir:
        testfiles = [os.path.join(opt.baseDir,opt.testDir,f) for f in os.listdir( os.path.join(opt.baseDir,opt.testDir) ) if f.endswith(opt.fileExt)]
    else:
        testfiles = None

    foldNumber=int(opt.folds)
    if not opt.foldList is None:
        foldList = opt.foldList.split(',')
    else:
        foldList = None
        
    generalizeMasks = (int(opt.generalizeMasks) == 1)
    
    if int(opt.searchEOF)==1:
        searchMethods=['START','EOF']
    else:
        searchMethods=['START','END']
        
    if foldNumber>1:
        if allfiles:
            # Perform cross-validation taking  allfiles as test set
            totalResults,models = doExperimentXval(allfiles,outFile=opt.outFile,
                             maxlen=int(opt.maxlen),
                             trainNumber=int(opt.maxFiles),
                             successThreshold=float(opt.successThreshold),
                             folds=foldNumber,foldsToRun=foldList,limits=limits,
                             generalizeMasks=generalizeMasks,
                             methods=searchMethods
                             )
            if opt.dumpFile:
                pickle.dump (models, open (opt.dumpFile,'wb'))
        else:
            raise RuntimeError ('ERROR: For training, please provide a correct clean and modified folders')
            
    else:
        if foldNumber==1:
            # Train with allfiles, test with test files (if any)
            # WARNING This option is old and must not be used due to insufficient testing. Use crossvalidation
            if allfiles:
                totalResults,models,matches = doExperimentSimple(trainset=allfiles,testset=testfiles,
                                models=None,
                                outFile=opt.outFile,
                                maxlen=int(opt.maxlen),
                                trainNumber=int(opt.maxFiles),
                                doTrain=True,
                                successThreshold=float(opt.successThreshold),
                                generalizeMasks=generalizeMasks,
                                methods=searchMethods
                                )
                if opt.dumpFile:
                    pickle.dump (models, open (opt.dumpFile,'wb'))
                if opt.dumpMatchesFile:
                    pickle.dump (matches, open (opt.dumpMatchesFile,'wb'))
            else:
                raise RuntimeError ('ERROR: For training, please provide a correct clean and modified folders')
            
        else:
            # Only test
            if int(opt.maxlen>0):
                logging.warning( "main: Called for test-only but we are using a nonzero maxlen value=%s", int(opt.maxlen))
                logging.warning( "main: Use maxlen=0 to test patterns on the whole file")
                
            if (os.path.isfile(opt.inputModels) and testfiles):
                logging.info( "main: Loading models from %s", opt.inputModels)
                modelsLoaded = pickle.load (open (opt.inputModels,'rb'))
                logging.info( "main: Loaded %s models", len(modelsLoaded))
                totalResults,models,matches = doExperimentSimple(trainset=None,testset=testfiles,
                                models=modelsLoaded,
                                outFile=opt.outFile,
                                maxlen=int(opt.maxlen),
                                doTrain=False)
            else:
                raise RuntimeError ('For test-only, please provide a valid models file and test directory')


if __name__ == "__main__": 
    main()
            
        

