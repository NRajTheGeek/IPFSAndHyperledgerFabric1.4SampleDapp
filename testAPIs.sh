#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

jq --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Please Install 'jq' https://stedolan.github.io/jq/ to execute this script"
	echo
	exit 1
fi
starttime=$(date +%s)

echo "POST request Enroll on Org1  ..."
echo
curl -X POST \
  http://localhost:3000/usersAPI/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=UserA&orgName=org1'

echo
echo "POST request Enroll on Org2 ..."
echo
curl -s -X POST \
  http://localhost:3000/usersAPI/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=UserB&orgName=org2'

echo 
echo "POST request Create channel  ..."
echo
curl -s -X POST \
  http://localhost:3000/channelsAPI/channels \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserA",
	"orgName": "org1",
	"channelName":"mychannel",
	"channelConfigPath":"../FABRIC/channel/mychannel.tx"
}'
echo
echo
sleep 5
echo "POST request Join channel on Org1"
echo
curl -s -X POST \
  http://localhost:3000/channelsAPI/channels/mychannel/peers \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserA",
	"orgName": "org1",
	"peers": ["peer0.org1.example.com","peer1.org1.example.com"]
}'
echo
echo

echo "POST request Join channel on Org2"
echo
curl -s -X POST \
  http://localhost:3000/channelsAPI/channels/mychannel/peers \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserB",
	"orgName": "org2",
	"peers": ["peer0.org1.example.com","peer1.org1.example.com"]
}'
echo
echo

echo "POST Install chaincode on Org1"
echo
curl -s -X POST \
  http://localhost:3000/chaincodesAPI/chaincodes \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserA",
	"orgName": "org1",
	"peers": ["peer1", "peer2"],
	"chaincodeName":"mycc",
	"chaincodePath":"github.com/doc_chaincode",
	"chaincodeVersion":"v0"
}'
echo
echo


echo "POST Install chaincode on Org2"
echo
curl -s -X POST \
  http://localhost:3000/chaincodesAPI/chaincodes \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserB",
	"orgName": "org2",
	"peers": ["peer0.org1.example.com","peer1.org1.example.com"],
	"chaincodeName":"mycc",
	"chaincodePath":"github.com/doc_chaincode",
	"chaincodeVersion":"v0"
}'
echo
echo

echo "POST instantiate chaincode on peer1 of Org1"
echo
curl -s -X POST \
  http://localhost:3000/chaincodesAPI/channels/mychannel/chaincodes \
  -H "content-type: application/json" \
  -d '{
  "userName": "UserA",
	"orgName": "org1",
	"chaincodeName":"mycc",
	"chaincodeVersion":"v0",
	"args":["init_for_chaincode", "0"]
}'
echo
echo


# echo "publisherA uploading a document for the user neeraj"
# echo
# RET_JSON=$(curl -s -X POST \
#   http://localhost:3000/channels/mychannel/chaincodes/mycc \
#   -H "content-type: application/json" \
#   -d '{
# 	"document": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABVYAAAMACAIAAABAXKuVAAAAA3NCSVQICAjb4U/gAAAAGXRFWHRTb2Z0d2FyZQBnbm9tZS1zY3JlZW5zaG907wO/PgAAIABJREFUeJzsnXd8VFX2wM99782bPpmZzKT3ngCBBEIvoSioWBBBRV1dXXdtu7a195VdV3/rqmtde1dQUEAQQXqvoYb0zKRNJmVmMn1euff3xyQhCQmSIIvrvu8ffMi777bz3szcc+455yJRFEBCQkJCQkJCQuJXDSGEDwUIxgwrRxRNUdT5HpGEhISExHmA4YKB8z0GCQkJCQkJCQmJc4vf71+79ofWFvv4ojHm6GhjZCQrl1MUfb7HNQgIIVzQjwWRABlsXQSIYmhWoUIInYuxSUhISPy3gPyejvM9BgkJCQkJCQkJiXNOU1PTm2/9e+u2bVmZmUVjCsaNHZuVlSWXKyn6v8MQ0OFyfPHl0ppaiyiKg61L03R6Wso1V18doTeci7FJSEhI/LeAvG7n+R6DhISEhISEhITEuYQQLIqiKLhcrjffevvNt99lKJgxKTdr2JTZF84aNmKEQqlE6JceGvDuO+8uX7HqbFqYf8Xlt/zu5p9rPBL/U4gCTzBhWPZ8D+TXgMBzRBQQzTAySZ7nAYZgfL7HIHHuQBgEGuhBe8tJSEhISEhI/AoghBDC85yzvb2srHTHrh2Hjx63WBqCgQAvCMSzr2r/kW0bvywcO+eO2++Mio2VyWQAv1w/+aqa2rNsobK6+uyXvhiLBBOapkGKKRgAAjJEvAjJz/USFAOrAA8H8nPcDwDArl27Wuwtl86dK1kBzp71634sq6jIycqac9Gc8z2W/0UkE8CvEwGZ7JzLJLhkolutNnkR+zN+BQsospnzmUSXmmpTsXEe+KVvGkhISEhISPxvEgj46+vrd+/e/d7770GgPMmMuSCIPlCwIGLYX05SY4MjUxttJ95fsGj3n++7e3rxdH1ExC9Ws8U/g/aOz37pW1traW1tLRw1Usayv2SLyWkgQIgoDnlxiAAQRQ+UVYGAvFbQGt1tifomL5V87qwAAjLZgm4T54rSmELAcejcGgK+WraivKICEzLvist/+S4zvzSwIABFdWchPXzk6OZt20PB0OzZF3begDFgTDHM+RvjIBDB1BxyR5F2owJ7IOJ8D2fQMIT0/z2IQdskyo18E0MEAoAQUiBBI3P5qMRBR1/9wuAgKhBqVGCeoUQDK3MjRfhiMNggJwKDeINC4QY5gKaOF6IFBwBtVgTdaAhPF7Vgs0xwqLAXCAYACiElzamYgBfFnDvTi4Ci7H6r9ZPnXz/e5Im+9rl782IVZvegFXXUSsyM4FCKHkQIANAIVHRIwWiPh1paV7325YkGV8SlT9wOJjZm8I1LSEhISEhInFOIx+NZunTJ9k0rS44ca2kP5CWTGhtE6iArAWKMYGuHdjdsPwrWZkiOVx87XvrI409dd83x2//w+0hT5FlptoQAAAn/CwQIAAIggBACFFYbh9z42auTZKCl75njdDoc7c59+w+MGVP4M/pNEIwFgR/cFBHQjGywhztgjLkWO64sB2Go54IxDJWZw0ZF9dc1VSZqow799fmPW6fc88erUxrcKA4AAOTV876543223456KiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiWWWWWWWWWWWWWWWWWWWWaaaaaaaaaaaaaaa",
# 	"pubisherId": "publisherA",
# 	"userId": "UserA"
# }')

# echo $RET_JSON

# echo "POST send the document for verification to the orderer"
# echo
# TRX_ID=$(curl -s -X POST \
#   http://localhost:3000/channels/mychannel/chaincodes/mycc \
#   -H "content-type: application/json" \
#   -d '{
# 	"fcn":"move",
# 	"args":["a","b","10"]
# }')
# echo "Transacton ID is $TRX_ID"
# echo
# echo

# echo "GET query chaincode on peer1 of Org1"
# echo
# curl -s -X GET \
#   "http://localhost:3000/channels/mychannel/chaincodes/mycc?peer=peer1&fcn=query&args=%5B%22a%22%5D" \
#   -H "content-type: application/json"
# echo
# echo

# echo "GET query Block by blockNumber"
# echo
# curl -s -X GET \
#   "http://localhost:3000/channels/mychannel/blocks/1?peer=peer1" \
#   -H "content-type: application/json"
# echo
# echo

# echo "GET query Transaction by TransactionID"
# echo
# curl -s -X GET http://localhost:3000/channels/mychannel/transactions/$TRX_ID?peer=peer1 \
#   -H "content-type: application/json"
# echo
# echo

# ############################################################################
# ### TODO: What to pass to fetch the Block information
# ############################################################################
# #echo "GET query Block by Hash"
# #echo
# #hash=????
# #curl -s -X GET \
# #  "http://localhost:3000/channels/mychannel/blocks?hash=$hash&peer=peer1" \
# #  -H "authorization: Bearer $ORG1_TOKEN" \
# #  -H "cache-control: no-cache" \
# #  -H "content-type: application/json" \
# #  -H "x-access-token: $ORG1_TOKEN"
# #echo
# #echo

# echo "GET query ChainInfo"
# echo
# curl -s -X GET \
#   "http://localhost:3000/channels/mychannel?peer=peer1" \
#   -H "content-type: application/json"
# echo
# echo

# echo "GET query Installed chaincodes"
# echo
# curl -s -X GET \
#   "http://localhost:3000/chaincodes?peer=peer1&type=installed" \
#   -H "content-type: application/json"
# echo
# echo

# echo "GET query Instantiated chaincodes"
# echo
# curl -s -X GET \
#   "http://localhost:3000/chaincodes?peer=peer1&type=instantiated" \
#   -H "content-type: application/json"
# echo
# echo

# echo "GET query Channels"
# echo
# curl -s -X GET \
#   "http://localhost:3000/channels?peer=peer1" \
#   -H "content-type: application/json"
# echo
# echo


# echo "Total execution time : $(($(date +%s)-starttime)) secs ..."
