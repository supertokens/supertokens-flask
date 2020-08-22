#!/usr/bin/env bash
coreDriverJson=`cat ../coreDriverInterfaceSupported.json`
coreDriverLength=`echo $coreDriverJson | jq ".versions | length"`
coreDriverArray=`echo $coreDriverJson | jq ".versions"`
echo "got core driver relations"

frontendDriverJson=`cat ../frontendDriverInterfaceSupported.json`
frontendDriverLength=`echo $frontendDriverJson | jq ".versions | length"`
frontendDriverArray=`echo $frontendDriverJson | jq ".versions"`
echo "got frontend driver relations"

# get driver version
version=`cat ../setup.py | grep -e 'version='`
while IFS='"' read -ra ADDR; do
    counter=0
    for i in "${ADDR[@]}"; do
        if [ $counter == 1 ]
        then
            version=$i
        fi
        counter=$(($counter+1))
    done
done <<< "$version"

responseStatus=`curl -s -o /dev/null -w "%{http_code}" -X PUT \
  https://api.supertokens.io/0/driver \
  -H 'Content-Type: application/json' \
  -H 'api-version: 0' \
  -d "{
	\"password\": \"$SUPERTOKENS_API_KEY\",
	\"version\":\"$version\",
    \"name\": \"flask\",
	\"frontendDriverInterfaces\": $frontendDriverArray,
	\"coreDriverInterfaces\": $coreDriverArray
}"`
if [ $responseStatus -ne "200" ]
then
    echo "failed core PUT API status code: $responseStatus. Exiting!"
	exit 1
fi

someTestsRan=false
i=0
while [ $i -lt $coreDriverLength ]; do
    coreDriverVersion=`echo $coreDriverArray | jq ".[$i]"`
    coreDriverVersion=`echo $coreDriverVersion | tr -d '"'`
    i=$((i+1))

    coreCommercial=`curl -s -X GET \
    "https://api.supertokens.io/0/core-driver-interface/dependency/core/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$coreDriverVersion" \
    -H 'api-version: 0'`
    if [[ `echo $coreCommercial | jq .core` == "null" ]]
    then
        echo "fetching latest X.Y version for core given core-driver-interface X.Y version: $coreDriverVersion, planType: COMMERCIAL gave response: $coreCommercial. Please make sure all relevant cores have been pushed."
        exit 1
    fi
    coreCommercial=$(echo $coreCommercial | jq .core | tr -d '"')

    coreFree=`curl -s -X GET \
    "https://api.supertokens.io/0/core-driver-interface/dependency/core/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$coreDriverVersion" \
    -H 'api-version: 0'`
    if [[ `echo $coreFree | jq .core` == "null" ]]
    then
        echo "fetching latest X.Y version for core given core-driver-interface X.Y version: $coreDriverVersion, planType: FREE gave response: $coreFree. Please make sure all relevant cores have been pushed."
        exit 1
    fi
    coreFree=$(echo $coreFree | jq .core | tr -d '"')

    someTestsRan=true
    ./setupAndTestWithCommercialCore.sh $coreCommercial
    if [[ $? -ne 0 ]]
    then
        echo "test failed... exiting!"
        exit 1
    fi
    rm -rf ../../com-root

    ./setupAndTestWithFreeCore.sh $coreFree
    if [[ $? -ne 0 ]]
    then
        echo "test failed... exiting!"
        exit 1
    fi
    rm -rf ../../supertokens-root
done

someFrontendTestsRan=false
i=0
coreDriverVersion=`echo $coreDriverArray | jq ". | last"`
coreDriverVersion=`echo $coreDriverVersion | tr -d '"'`
coreCommercial=`curl -s -X GET \
    "https://api.supertokens.io/0/core-driver-interface/dependency/core/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$coreDriverVersion" \
    -H 'api-version: 0'`
if [[ `echo $coreCommercial | jq .core` == "null" ]]
then
    echo "fetching latest X.Y version for core given core-driver-interface X.Y version: $coreDriverVersion, planType: COMMERCIAL gave response: $coreCommercial. Please make sure all relevant cores have been pushed."
    exit 1
fi
coreCommercial=$(echo $coreCommercial | jq .core | tr -d '"')
while [ $i -lt $frontendDriverLength ]; do
    frontendDriverVersion=`echo $frontendDriverArray | jq ".[$i]"`
    frontendDriverVersion=`echo $frontendDriverVersion | tr -d '"'`
    i=$((i+1))

    if [[ $frontendDriverVersion == '1.0' ]]; then
        continue
    fi

    frontendVersionXY=`curl -s -X GET \
    "https://api.supertokens.io/0/frontend-driver-interface/dependency/frontend/latest?password=$SUPERTOKENS_API_KEY&frontendName=website&mode=DEV&version=$frontendDriverVersion" \
    -H 'api-version: 0'`
    if [[ `echo $frontendVersionXY | jq .frontend` == "null" ]]
    then
        echo "fetching latest X.Y version for frontend given frontend-driver-interface X.Y version: $frontendDriverVersion, name: webiste gave response: $frontend. Please make sure all relevant cores have been pushed."
        exit 1
    fi
    frontendVersionXY=$(echo $frontendVersionXY | jq .frontend | tr -d '"')

    frontendInfo=`curl -s -X GET \
    "https://api.supertokens.io/0/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$frontendVersionXY&name=website" \
    -H 'api-version: 0'`
    if [[ `echo $frontendInfo | jq .tag` == "null" ]]
    then
        echo "fetching latest X.Y.Z version for frontend, X.Y version: $frontendVersionXY gave response: $frontendInfo"
        exit 1
    fi
    frontendTag=$(echo $frontendInfo | jq .tag | tr -d '"')
    frontendVersion=$(echo $frontendInfo | jq .version | tr -d '"')

    nodeVersionXY=`curl -s -X GET \
    "https://api.supertokens.io/0/frontend-driver-interface/dependency/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$frontendDriverVersion&driverName=node" \
    -H 'api-version: 0'`
    if [[ `echo $nodeVersionXY | jq .driver` == "null" ]]
    then
        echo "fetching latest X.Y version for driver given frontend-driver-interface X.Y version: $frontendDriverVersion gave response: $nodeVersionXY. Please make sure all relevant drivers have been pushed."
        exit 1
    fi
    nodeVersionXY=$(echo $nodeVersionXY | jq .driver | tr -d '"')

    nodeInfo=`curl -s -X GET \
    "https://api.supertokens.io/0/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$nodeVersionXY&name=node" \
    -H 'api-version: 0'`
    if [[ `echo $nodeInfo | jq .tag` == "null" ]]
    then
        echo "fetching latest X.Y.Z version for driver, X.Y version: $nodeVersionXY gave response: $nodeInfo"
        exit 1
    fi
    nodeTag=$(echo $nodeInfo | jq .tag | tr -d '"')

    ./setupAndTestWithFrontend.sh $coreCommercial $frontendTag $nodeTag
    if [[ $? -ne 0 ]]
    then
        echo "test failed... exiting!"
        exit 1
    fi
    someFrontendTestsRan=true
    rm -rf ../../com-root
done

if [[ $someFrontendTestsRan = "true" ]] && [[ $someTestsRan = "true" ]]
then
    echo "calling /driver PATCH to make testing passed"
    responseStatus=`curl -s -o /dev/null -w "%{http_code}" -X PATCH \
        https://api.supertokens.io/0/driver \
        -H 'Content-Type: application/json' \
        -H 'api-version: 0' \
        -d "{
            \"password\": \"$SUPERTOKENS_API_KEY\",
            \"version\":\"$version\",
            \"name\": \"flask\",
            \"testPassed\": true
        }"`
    if [ $responseStatus -ne "200" ]
    then
        echo "patch api failed"
        exit 1
    fi
else
    echo "no test ran"
    exit 1
fi