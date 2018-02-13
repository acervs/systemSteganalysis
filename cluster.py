from scipy.cluster.hierarchy import dendrogram, linkage, fcluster
import scipy.spatial.distance as dist
import numpy as np
import pickle
from binascii import unhexlify
from systemAnalysisUtils import getMaskFromPattern

#
# Utility Functions
#
# data=[]

def distanceMeasure(coord,data):
    i, j = coord
    return dist.hamming(data[i], data[j])

def distanceMeasure2(coord,data):
    i, j = coord
    d = 0
    if not len(data[i]) == len(data[j]):
        distance2 = 1.0
    else:
        length=min(len(data[i]),len(data[j]))
        for p in range(length):
            if not data[i][p] == data[j][p]:
                d+=1
        distance2 = d/float(length)
            
    return distance2


def generateVarPatterns (cl):
    patterns=[]
    for c in cl:
        # Replace variable parts with ??
        p  = buildPatternFromMaskList (c)
        # P is now a standard pattern, verify
        m = getMaskFromPattern(p)
        print 'Extracted pattern mask: ' , m
        patterns.append (p)
    return patterns


def getClusters (clusters,minLength):
    clist=[]
    for cluster in set(clusters.tolist()):
        n = list ( i for i,v in enumerate(clusters.tolist()) if v == cluster)
#        print 'Cluster ', cluster, ' n=', n
        if ( len(n) >= minLength ):
            clist.append (n)
    return clist

def getClusterMasks (data,cluster):
    clmask=[]
    for i in cluster:
        m=''.join(data[i])
        clmask.append (m)
    return clmask

def getAllClusterMasks (data,clusters,number):
    clist=getClusters (clusters,minLength=number)
    cmasks=[]
    for c in clist:
        cmasks.append (getClusterMasks (data,c))
    return cmasks

def clusterList (Z,data,threshold,number):
    clusters = fcluster(Z,threshold,criterion='distance')
    return getAllClusterMasks (data,clusters,number)

def getChunks (maskList, chunkNumber, chunk=2):
    return list ( s[chunkNumber*chunk*2:(chunkNumber+1)*chunk*2] for s in maskList )

def buildPatternFromMaskList (maskList,chunk=2):
    pattern=[]
    # Original length in bytes for a pattern means chunks are of 16 bits
    maskLength=len(maskList[0])/(chunk*2)
    for chunkNumber in range(maskLength):
        chunks = getChunks (maskList, chunkNumber, chunk)
        if all (x==chunks[0] for x in chunks):
            pattern.append ((0,True,unhexlify(chunks[0]),unhexlify(chunks[0])))
        else:
            pattern.append ((1,False,unhexlify(chunks[0]),unhexlify(chunks[0])))
    return pattern

#
# Load the masks obtained by a call to collecPatterns
# pmasks = pickle.load (open ('oef1pmasks1.p','rb'))
#
# For clustering we need a list where each element is a list
# of digits or bytes
#

# ohFiles=do.sy.readFileList(baseDir='../../data/ukent',coverDir='Videos - All Formats/MP4',
#        stegoDir='StegoArchive/OmniHide Tests/OHPRVideos',coverSuffix='',stegoSuffix='_Out',extension='mp4')
# ohFiles=do.purgeFileList(ohFiles)
# trainfiles = ohFiles[0:10]
# testfiles = ohFiles[10:]

# patterns,pmasks = do.sy.collectPatternsEOFInjection (trainfiles,maxlen=1024*4)
# clusteredPatterns,clusteredMasks = getClusteredPatterns(data,Z,0.20,3)
# extractedPatterns={ 'generated':newPatterns }
#


def hierarchicalCluster (pmasks,useUnique=True):
    '''
        Clustering requires a matrix with the distances between any two points in the data
        This is serialized into a list that pairs values d(0,0), d(0,1), ... , d(1,2).. etc.
        To invoke np.apply_along_axis we first construct the triangular indices tuple whose
        elements are then paired when calculating each value in the distance matrix.
        Then, the linkage function is called with the distance data
        
        Example:
            >>> y
            [0, 1, 2, 3, 4]
            >>> ind[0]
            array([0, 0, 0, 0, 1, 1, 1, 2, 2, 3])
            >>> ind[1]
            array([1, 2, 3, 4, 2, 3, 4, 3, 4, 4])
            >>> y
            [0, 1, 2, 3, 4]
            >>> ind=np.triu_indices(5,1)
            >>> ind[0]
            array([0, 0, 0, 0, 1, 1, 1, 2, 2, 3])
            >>> ind[1]
            array([1, 2, 3, 4, 2, 3, 4, 3, 4, 4])
            >>> distmatrix = np.apply_along_axis (mydist,0,ind,y)
            >>> distmatrix
            array([1, 2, 3, 4, 1, 2, 3, 1, 2, 1])
    '''
    data=[]
    uniqueMasks = set()
    if useUnique:
        for k,v in pmasks.items():
            for m in v:
                uniqueMasks.add (m)
    
        for m in uniqueMasks:
            data.append( list(m))
    else:
        for k,v in pmasks.items():
            for m in v:
                data.append (list(m))
            
            
    # This was taken from a clustering tutorial
    ci = np.triu_indices (len(data),1)
    ca = np.apply_along_axis(distanceMeasure,0,ci,data)
    Z  = linkage(ca)
    return Z,data,ca,uniqueMasks

def hierarchicalCluster2 (pmasks,useUnique=True,distanceMeasure=distanceMeasure2):
    data=[]
    uniqueMasks = set()
    if useUnique:
        for k,v in pmasks.items():
            for m in v:
                uniqueMasks.add (m)
    
        for m in uniqueMasks:
            data.append( list(m))
    else:
        for k,v in pmasks.items():
            for m in v:
                data.append (list(m))
            
            
    # This was taken from a clustering tutorial
    ci = np.triu_indices (len(data),1)
    ca = np.apply_along_axis(distanceMeasure,0,ci,data)
    Z  = linkage(ca)
    return Z,data,ca,uniqueMasks


def getClusteredPatterns(data,Z,threshold,groupSize):
    """
        The distance function passed to np.apply_along_axis depends on the global
        variable 'data'
    """
    
    
    #
    # With the linkage table we can obtain clusters
    # The threshold and number of patterns in the cluster
    # are important parameters
    #
    # Get clusters of at least three patterns with strict threshold
    clusteredMasks = clusterList (Z, data, threshold , groupSize)
    
    # Now construct a model based on the new patterns
    # These patterns will have variable parts so they will match
    # more files
    
    clusteredPatterns=[]
    for m in clusteredMasks:
        clusteredPatterns.append (buildPatternFromMaskList(m))

    return clusteredPatterns,clusteredMasks

    '''
        def mydist(coord,data):
            i,j = coord
            return abs(data[j]-data[i])
    
        def getIndexes (n):
            return np.asarray( list ([i]*n for i in range (n) )).flatten()
            
        def minDist(coord,data):
            i,j = coord
            x = np.array([data[i],data[j]])
            sz = len(data[i])
            ind = ( getIndexes(sz), np.array( range(sz,2*sz)*sz ) )
            y = x.flatten()
            distmatrix = np.apply_along_axis (mydist,0,ind,y)
            minDist = min(distmatrix)
            minIndex = distmatrix.tolist().index(min(distmatrix))
            
        
    '''
