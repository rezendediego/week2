pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
//Included to compute MerkleTreeInclusionProof(n)
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

//The solution is inspired by Tornado ( file merkleTree.circom )
//Helper Template to calculate hash of items 2 by 2 
//and throw an output array with the hashed items of the layer  
template LayerHasher(depth){
    //Declare variable tha guides the number of items per layer
    var numOfLeaves = 2**depth;
    
    //Declare array input signals of hashed items 
    //that will be taken and hashed 2 by 2 for next Tree layer
    signal input inHashedItems[numOfLeaves * 2];
    
    //Declare array output signals that holds the computed hashed 
    //items of the inserted depth Tree layer
    signal output outHashedItems[numOfLeaves];
    
    //Declare component hash array of numOfLeaves items
    //where each  position will be an instantiation of Poseidon 
    //template with two inputs and its out will then be stored
    //at outHashedItems array
    component hash[numOfLeaves];
    
    //Loop to compute hashes 2by2 items and fill outHashedItems array with it
    for(var i = 0; i < numOfLeaves; i++) {
      hash[i] = Poseidon(2);
      hash[i].inputs[0] <== inHashedItems[i * 2];
      hash[i].inputs[1] <== inHashedItems[i * 2 + 1];
      hash[i].out ==> outHashedItems[i];
    }
 
}

//The solution is inspired by Tornado ( file merkleTree.circom )
template CheckRoot(n) { // compute the root of a MerkleTree of n Levels 
    signal input leaves[2**n];
    signal output root;
    //[assignment] insert your code here to calculate the Merkle root from 2^n leaves
    
    //Declare component treeLayers array of size n (representing each tree layers ) 
    //in which every layer is an instatiation of template LayerHasher where
    //outHashedItems represents the hashed items within it  
    component treeLayers[n];
    
    //Loop to navigate tree per levels from farthest up to its root
    for(var level = n - 1; level >= 0; level--) {
       
       //Instantiation of component treeLayers in specifc level to 
       //its LayerHasher template with same level
       treeLayers[level] = LayerHasher(level);
       
       //Loop to populate the input (inHashedItems) from component treeLayers
       for(var i = 0; i < (1 << (level + 1)); i++) {
          
          //Fill Every item from treeLayers input inHashedItems with initial leaves
          //array input items if we are computing treeLayers[level n-1] otherwise
          //fill the inHashedItems with the outHashedItems of previous computed hashed layer
          treeLayers[level].inHashedItems[i] <== level == n - 1 ? leaves[i] : treeLayers[level + 1].outHashedItems[i];
        }
    }

    //Boolean Conditional where in an existing Merkle Tree with n>0
    //root receives the value of treeLayers[0].outHashedItems[0]
    //Otherwise, receives the leaves[0] unique item
    root <== n > 0 ? treeLayers[0].outHashedItems[0] : leaves[0];
     
}



//The solution is inspired by Tornado ( file merkleProof.circom )
//It also demonstrates how to use switcher.circom

/*
    Assume sel is binary.

    If sel == 0 then outL = L and outR=R
    If sel == 1 then outL = R and outR=L

 */

template MerkleTreeInclusionProof(n) {
    signal input leaf;
    signal input path_elements[n];
    signal input path_index[n]; // path index are 0's and 1's indicating whether the current element is on the left or right
    signal output root; // note that this is an OUTPUT signal

    //[assignment] insert your code here to compute the root from a leaf and elements along the path
    
    component switcher[n];
    component hasher[n];
    component indexBits[n];
    
    //Loop to fill the component indexBits array with the direction 
    //Left(0) or Right(1) index in binary form of n bits
    for( var index = 0; index<n; index++){
        indexBits[index]= Num2Bits(4);
        indexBits[index].in <== path_index[index];
    }
   
    //Loop to use component switcher to position proval elements
    //acording its path direction index and component hasher that
    //will compute 2 by 2 hashes up to the proof root 
    for (var i = 0; i < n; i++) {
        switcher[i] = Switcher();
        switcher[i].L <== i == 0 ? leaf : hasher[i - 1].out;
        switcher[i].R <== path_elements[i];
        switcher[i].sel <== indexBits[i].out[i];

        hasher[i] = Poseidon(2);
        hasher[i].inputs[0] <== switcher[i].outL;
        hasher[i].inputs[1] <== switcher[i].outR;
    }

    root <== hasher[n - 1].out;
}