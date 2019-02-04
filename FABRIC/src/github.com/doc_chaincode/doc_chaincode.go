/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

// ============================================================================================================================
// Asset Definitions - The ledger will store documents and owners
// ============================================================================================================================

const STATE_DOCUMENT_CREATED = 1
const STATE_DOCUMENT_VERIFIED = 2
const STATE_DOCUMENT_REJECTED = 3
const STATE_DOCUMENT_UPDATED = 4

type Document struct {
	DocumentChannel   string `json:"docChannel"` //docType is used to distinguish the various types of objects in state database
	publisherUUID     string `json:"publisherUUID"`
	ownerUUID         string `json:"ownerUUID"`
	DocumentHash      string `json:"documentHash"`
	DocumentStatus    string `json:"documentStatus"`
	OwnerPublicKey    string `json:"ownerPublicKey"`
	VerifierPublicKey string `json:"verifierPublicKey"`
	CreatedON         string `json:"createdOn"`
}

// ============================================================================================================================
// Main
// ============================================================================================================================
func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode - %s", err)
	}
}

// ============================================================================================================================
// Init - initialize the chaincode
//
// Documents does not require initialization, so let's run a simple test instead.
//
// Shows off PutState() and how to pass an input argument to chaincode.
// Shows off GetFunctionAndParameters() and GetStringArgs()
// Shows off GetTxID() to get the transaction ID of the proposal
//
// Inputs - Array of strings
//  ["314"]
//
// Returns - shim.Success or error
// ============================================================================================================================
func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("Document Store Channel Is Starting Up")
	funcName, args := stub.GetFunctionAndParameters()
	var err error
	txId := stub.GetTxID()

	fmt.Println("  Init() is running")
	fmt.Println("  Transaction ID: ", txId)
	fmt.Println("  GetFunctionAndParameters() function: ", funcName)
	fmt.Println("  GetFunctionAndParameters() args count: ", len(args))
	fmt.Println("  GetFunctionAndParameters() args found: ", args)

	// expecting 1 arg for instantiate or upgrade
	if len(args) == 2 {
		fmt.Println("  GetFunctionAndParameters() : Number of arguments", len(args))
	}
	// this is a very simple test. let's write to the ledger and error out on any errors
	// it's handy to read this right away to verify network is healthy if it wrote the correct value
	err = stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return shim.Error(err.Error()) //self-test fail
	}

	fmt.Println("Ready for action") //self-test pass
	return shim.Success(nil)
}

// ============================================================================================================================
// Invoke - Our entry point for Invocations
// ============================================================================================================================
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	fmt.Println(" ")
	fmt.Println("starting invoke, for - " + function)

	// Handle different functions
	if function == "init_document" { //create a new marble
		return init_document(stub, args)
	} else if function == "update_document" { //create a new marble
		return update_document(stub, args)
	} else if function == "queryDocumentsByStatus" {
		return queryDocumentsByStatus(stub, args)
	} else if function == "queryDocumentStatusByHash" {
		return queryDocumentStatusByHash(stub, args)
	}

	// error out
	fmt.Println("Received unknown invoke function name - " + function)
	return shim.Error("Received unknown invoke function name - '" + function + "'")
}

// ============================================================================================================================
// Query - legacy function
// ============================================================================================================================
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Error("Unknown supported call - Query()")
}

// ============================================================================================================================
// Read - read a generic variable from ledger
//
// Shows Off GetState() - reading a key/value from the ledger
//
// Inputs - Array of strings
//  0
//  key
//  "abc"
//
// Returns - string
// ============================================================================================================================
func read(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var key, jsonResp string
	var err error
	fmt.Println("starting read")

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting key of the var to query")
	}

	// input sanitation
	err = sanitize_arguments(args)
	if err != nil {
		return shim.Error(err.Error())
	}

	key = args[0]
	valAsbytes, err := stub.GetState(key) //get the var from ledger
	if err != nil {
		jsonResp = "{\"Error\":\"Failed to get state for " + key + "\"}"
		return shim.Error(jsonResp)
	}

	fmt.Println("- end read")
	return shim.Success(valAsbytes) //send it onward
}

func read_everything(stub shim.ChaincodeStubInterface) pb.Response {
	type Everything struct {
		Documents []Document `json:"documents"`
	}
	var everything Everything

	// ---- Get All Documents ---- //
	resultsIterator, err := stub.GetStateByRange("m0", "m9999999999999999999")
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		aKeyValue, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}
		queryKeyAsStr := aKeyValue.Key
		queryValAsBytes := aKeyValue.Value
		fmt.Println("on document id - ", queryKeyAsStr)
		var document Document
		json.Unmarshal(queryValAsBytes, &document)                    //un stringify it aka JSON.parse()
		everything.Documents = append(everything.Documents, document) //add this marble to the list
	}
	fmt.Println("documents array - ", everything.Documents)

	//change to array of bytes
	everythingAsBytes, _ := json.Marshal(everything) //convert to array of bytes
	return shim.Success(everythingAsBytes)
}

// ============================================================================================================================
// Get history of asset
//
// Shows Off GetHistoryForKey() - reading complete history of a key/value
//
// Inputs - Array of strings
//  0
//  id
//  "m01490985296352SjAyM"
// ============================================================================================================================
func getHistory(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	type AuditHistory struct {
		TxId  string   `json:"txId"`
		Value Document `json:"value"`
	}
	var history []AuditHistory
	var document Document

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	documentId := args[0]
	fmt.Printf("- start getHistoryForMarble: %s\n", documentId)

	// Get History
	resultsIterator, err := stub.GetHistoryForKey(documentId)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		historyData, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}

		var tx AuditHistory
		tx.TxId = historyData.TxId                   //copy transaction id over
		json.Unmarshal(historyData.Value, &document) //un stringify it aka JSON.parse()
		if historyData.Value == nil {                //marble has been deleted
			var emptyDocument Document
			tx.Value = emptyDocument //copy nil marble
		} else {
			json.Unmarshal(historyData.Value, &document) //un stringify it aka JSON.parse()
			tx.Value = document                          //copy marble over
		}
		history = append(history, tx) //add this tx to the list
	}
	fmt.Printf("- getHistoryForDocument returning:\n%s", history)

	//change to array of bytes
	historyAsBytes, _ := json.Marshal(history) //convert to array of bytes
	return shim.Success(historyAsBytes)
}

// ============================================================================================================================
// Get Document - get a document asset from ledger
// ============================================================================================================================
func get_document(stub shim.ChaincodeStubInterface, id string) (Document, error) {
	doc := Document{}
	documentAsBytes, err := stub.GetState(id) //getState retreives a key/value from the ledger
	if err == nil {                           //this seems to always succeed, even if key didn't exist
		return doc, errors.New("Failed to find marble - " + id)
	}

	/*fmt.Println("document id from document is " + document.DocumentID)
	fmt.Println("document id of requested document is " + id)*/

	if documentAsBytes == nil { //test if marble is actually here or just nil
		return doc, errors.New("Document does not exist - " + id)
	}

	err = json.Unmarshal([]byte(documentAsBytes), &doc)
	if err != nil {
		fmt.Println("Unmarshal failed : ", err)
		return doc, errors.New("unable to unmarshall")
	}

	fmt.Println(doc)
	return doc, nil
}

// ========================================================
// Input Sanitation - dumb input checking, look for empty strings
// ========================================================
func sanitize_arguments(strs []string) error {
	for i, val := range strs {
		if len(val) <= 0 {
			return errors.New("Argument " + strconv.Itoa(i) + " must be a non-empty string")
		}
		// if len(val) > 32 {
		// 	return errors.New("Argument " + strconv.Itoa(i) + " must be <= 32 characters")
		// }
	}
	return nil
}

// ============================================================================================================================
// write() - genric write variable into ledger
//
// Shows Off PutState() - writting a key/value into the ledger
//
// Inputs - Array of strings
//    0   ,    1
//   key  ,  value
//  "abc" , "test"
// ============================================================================================================================
func write(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var key, value string
	var err error
	fmt.Println("starting write")

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2. key of the variable and value to set")
	}

	// input sanitation
	err = sanitize_arguments(args)
	if err != nil {
		return shim.Error(err.Error())
	}

	key = args[0] //rename for funsies
	value = args[1]
	err = stub.PutState(key, []byte(value)) //write the variable into the ledger
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end write")
	return shim.Success(nil)
}

func init_document(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	fmt.Println("starting init_document")

	if len(args) != 7 {
		fmt.Println("initDocument(): Incorrect number of arguments. Expecting 7 ")
		return shim.Error("intDocument(): Incorrect number of arguments. Expecting 7 ")
	}

	//input sanitation
	err1 := sanitize_arguments(args)
	if err1 != nil {
		return shim.Error("Cannot sanitize arguments")
	}

	documentHash := args[3]
	documentStatus := args[4]

	//check if marble id already exists
	documentAsBytes, err := stub.GetState(documentHash)
	if err != nil { //this seems to always succeed, even if key didn't exist
		return shim.Error("error in finding document for - " + documentHash)
	}
	if documentAsBytes != nil {
		fmt.Println("This document already exists - " + documentHash)
		return shim.Error("This document already exists - " + documentHash) //all stop a marble by this id exists
	}

	if documentStatus != strconv.Itoa(STATE_DOCUMENT_CREATED) {
		return shim.Error(" Invalid document status - " + documentStatus + "Expecting document status unverified - 1") //all stop a marble by this id exists
	}

	documentObject, err := CreateDocumentObject(args[0:])
	if err != nil {
		errorStr := "initDocument() : Failed Cannot create object buffer for write : " + args[0]
		fmt.Println(errorStr)
		return shim.Error(errorStr)
	}

	fmt.Println(documentObject)
	buff, err := DOCtoJSON(documentObject)
	if err != nil {
		return shim.Error("unable to convert document to json")
	}
	// =================================================
	noUse, err := JSONtoDoc(buff)
	if err != nil {
		return shim.Error("unable to unmarshel back from the marshelled data")
	}
	fmt.Println("after unmarshelling the marshelled doc ")
	fmt.Println(noUse)

	//==================================================

	err = stub.PutState(documentHash, buff) //store marble with id as key
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end init_document")
	return shim.Success(nil)
}

// CreateAssetObject creates an asset
func CreateDocumentObject(args []string) (Document, error) {
	var myDocument Document

	// Check there are 10 Arguments provided as per the the struct
	if len(args) != 7 {
		fmt.Println("CreateDocumentObject(): Incorrect number of arguments. Expecting 7 ")
		return myDocument, errors.New("CreateDocumentObject(): Incorrect number of arguments. Expecting 7 ")
	}

	myDocument = Document{args[0], args[1], args[2], args[3], args[4], args[5], args[6], time.Now().Format("20060102150405")}
	return myDocument, nil
}

func DOCtoJSON(doc Document) ([]byte, error) {

	fmt.Println("doc before being marshelled")
	fmt.Println(doc)

	djson, err := json.Marshal(doc)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return djson, nil
}

func JSONtoDoc(data []byte) (Document, error) {

	doc := Document{}
	err := json.Unmarshal([]byte(data), &doc)
	if err != nil {
		fmt.Println("Unmarshal failed : ", err)
		return doc, err
	}

	return doc, nil
}

func queryDocumentsByStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	document_channel := args[0]
	status := strings.ToLower(args[1])

	queryString := fmt.Sprintf("{\"selector\":{\"docChannel\":\"%s\",\"documentStatus\":\"%s\"}}", document_channel, status)

	queryResults, err := getQueryResultForQueryString(stub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(queryResults)
}

func queryDocumentStatusByHash(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	//   0
	// "bob"
	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	document_hash := args[0]
	queryString := fmt.Sprintf("{\"selector\":{\"documentHash\":\"%s\"}}", document_hash)

	queryResults, err := getQueryResultForQueryString(stub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(queryResults)
}

func getQueryResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	fmt.Printf("- getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	// buffer is a JSON array containing QueryRecords
	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		// Add a comma before array members, suppress it for the first array member
		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		// Record is a JSON object, so we write as-is
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	fmt.Printf("- getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

func update_document(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error
	fmt.Println("starting update_document")

	if len(args) != 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	//input sanitation
	err = sanitize_arguments(args)
	if err != nil {
		return shim.Error(err.Error())
	}

	document_hash := args[0]
	document_Status := args[1]

	documentAsBytes, err := stub.GetState(document_hash)
	str := fmt.Sprintf("%s", documentAsBytes)
	fmt.Println("string is " + str)

	if err != nil { //this seems to always succeed, even if key didn't exist
		fmt.Println("Error in finding Document - " + document_hash)
		return shim.Error("error in finding document for - " + document_hash)
	}
	/*if len(documentAsBytes) == 0 {
		fmt.Println("This document already exists and is null- " + document_ID)
		return shim.Error("This document already exists but is null - " + document_ID) //all stop a marble by this id exists
	}*/

	list := []string{strconv.Itoa(STATE_DOCUMENT_REJECTED), strconv.Itoa(STATE_DOCUMENT_VERIFIED)}

	if !(stringInSlice(document_Status, list)) {
		return shim.Error(" Invalid document update status - " + document_Status + "Expecting document status verified/Rejected - 2 || 3") //all stop a marble by this id exists
	}

	dat, err := JSONtoDoc(documentAsBytes)
	if err != nil {
		return shim.Error("unable to convert jsonToDoc for" + document_hash)
	}

	updatedDocument := Document{dat.DocumentChannel, dat.publisherUUID, dat.ownerUUID, dat.DocumentHash, document_Status, dat.OwnerPublicKey, dat.VerifierPublicKey, time.Now().Format("20060102150405")}

	buff, err := DOCtoJSON(updatedDocument)
	if err != nil {
		errorStr := "updateDispatchOrder() : Failed Cannot create object buffer for write : " + args[1]
		fmt.Println(errorStr)
		return shim.Error(errorStr)
	}

	err = stub.PutState(dat.DocumentHash, buff) //store marble with id as key
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end init_document")
	return shim.Success(nil)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
