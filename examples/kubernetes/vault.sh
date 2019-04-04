#!/bin/bash

#*****K8s Config*****
vault auth enable kubernetes

#Create service accounts
kubectl create serviceaccount --namespace=default vault
kubectl create serviceaccount --namespace=default go

#Give permissions to the Vault account
kubectl create clusterrolebinding vault --clusterrole=system:auth-delegator --serviceaccount=default:vault

#Get the JWT
ACCOUNT_SECRET=$(kubectl --namespace=default get serviceaccounts vault -o json | jq -r .secrets[0].name)
ACCOUNT_JWT=$(kubectl --namespace=default  get secret ${ACCOUNT_SECRET}  -o json | jq -r .data.token | base64 --decode)

#Create the config - PLACE YOUR K8s CERT IN THE DIR YOU ARE RUNNING THIS SCRIPT!
vault write auth/kubernetes/config \
    token_reviewer_jwt=${ACCOUNT_JWT} \
    kubernetes_host=https://127.0.0.1  \
    kubernetes_ca_cert=@ca.crt

#Create the roles
vault write auth/kubernetes/role/order \
    bound_service_account_names=go \
    bound_service_account_namespaces=default \
    policies=order \
    period=30m
