//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import { PoseidonT3 } from "./Poseidon.sol"; //an existing library to perform Poseidon hash on solidity
import "./verifier.sol"; //inherits with the MerkleTreeInclusionProof verifier contract

/**
        __________           _____________________
         indexing                 Merkle Tree 
        convention                  3 levels   
        ***********          *********************

          3--->                   #### 14 ####  ---> ROOT
                                 /            \
          2--->                12              13
                            /      \        /      \
          1--->            08      09      10      11
                          /  \    /  \    /  \    /  \
          0--->          00  01  02  03  04  05  06  07  ---> 8 initial leaves  

         Flattened Tree Layer must be initialized with zeroes and look like below:
         hashes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                   |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
                   0  1  2  3  4  5  6  7  8  9  10 11 12 13 14
         */

contract MerkleTree is Verifier {
    uint256[] public hashes; // the Merkle tree in flattened array form
    uint256 public index = 0; // the current index of the first unfilled leaf
    uint256 public root; // the current Merkle root
    

    constructor() {
        // [assignment] initialize a Merkle tree of 8 with blank leaves
        //Initializing hashes to 15 positions 
        hashes = new uint256[](15);
        
        uint256 exp = index/uint256(2);

        //Filling layer 3
        for(uint i=0; i<8; i++){
            hashes[i] = 0;
        }
        //Filling layer 2
        for(uint i = 0; i<=6; i+=2){
            hashes[7+(2**exp)] = PoseidonT3.poseidon([hashes[i],hashes[i+1]]);
        }
        //Filling layer 1
        for(uint i = 8; i<=10; i+=2){
            hashes[11+(2**(exp/uint256(2)))] = PoseidonT3.poseidon([hashes[i],hashes[i+1]]);
        }
        //Filling First Root
        hashes[14] = PoseidonT3.poseidon([hashes[12],hashes[13]]);
    }

    
    function insertLeaf(uint256 hashedLeaf) public returns (uint256) {
        // [assignment] insert a hashed leaf into the Merkle tree
        require(index<8,"Merkle Tree Initial Leaves Limit complete");
        
        hashes[index] = hashedLeaf;
        uint256 exp = index/uint256(2);
        
        for(uint i=index; i<15 ; i++){
            // Is even?
            if(index % 2 == 0){
                   hashes[7+(2**exp)] = PoseidonT3.poseidon([hashes[index], hashes[index+1]]);
                   // Is even?
                   if((7+(2**exp)) % 2 == 0){
                            hashes[11+(2**(exp/uint256(2)))] = PoseidonT3.poseidon([hashes[(7+(2**exp))], hashes[(7+(2**exp))+1]]);
                            // Is even?
                            if((11+(2**(exp/uint256(2)))) % 2 == 0){
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))], hashes[(11+(2**(exp/uint256(2))))+1]]);
                                root = hashes[14];
                            }else{//odd path
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))-1], hashes[(11+(2**(exp/uint256(2))))]]);
                                root = hashes[14];
                            }                        
                    }else{//odd path/////////////////////////
                            hashes[11+(2**(exp/uint256(2)))] = PoseidonT3.poseidon([ hashes[(7+(2**exp))-1],hashes[(7+(2**exp))]]);
                            // Is even?
                            if((11+(2**(exp/uint256(2)))) % 2 == 0){
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))], hashes[(11+(2**(exp/uint256(2))))+1]]);
                                root = hashes[14];
                            }else{//odd path/////////////////////////
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))-1], hashes[(11+(2**(exp/uint256(2))))]]);
                                root = hashes[14];
                            }     
                    }
            }else{//odd path/////////////////////////
                   hashes[7+(2**exp)] = PoseidonT3.poseidon([hashes[index-1], hashes[index]]);
                   // Is even?
                   if((7+(2**exp)) % 2 == 0){
                            hashes[11+(2**(exp/uint256(2)))] = PoseidonT3.poseidon([hashes[(7+(2**exp))], hashes[(7+(2**exp))+1]]);
                            // Is even?
                            if((11+(2**(exp/uint256(2)))) % 2 == 0){
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))], hashes[(11+(2**(exp/uint256(2))))+1]]);
                                root = hashes[14];
                            }else{//odd path
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))-1], hashes[(11+(2**(exp/uint256(2))))]]);
                                root = hashes[14];
                            }                        
                    }else{//odd path/////////////////////////
                            hashes[11+(2**(exp/uint256(2)))] = PoseidonT3.poseidon([ hashes[(7+(2**exp))-1],hashes[(7+(2**exp))]]);
                            // Is even?
                            if((11+(2**(exp/uint256(2)))) % 2 == 0){
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))], hashes[(11+(2**(exp/uint256(2))))+1]]);
                                root = hashes[14];
                            }else{//odd path/////////////////////////
                                hashes[14] = PoseidonT3.poseidon([hashes[(11+(2**(exp/uint256(2))))-1], hashes[(11+(2**(exp/uint256(2))))]]);
                                root = hashes[14];
                            }     
                    }            
            }
        }        
        return root;
    }

    function verify(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[1] memory input
        ) public view returns (bool) {

        // [assignment] verify an inclusion proof and check that the proof root matches current root
        // Returning function verifyProof from Verifier contract 
        return verifyProof(a, b, c, input);
    }
}
