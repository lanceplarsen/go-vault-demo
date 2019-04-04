# go-vault-demo-kubernetes

This folder will help you deploy the sample app to Kubernetes.

To establish trust between the K8s you can run the [vault script](vault.sh) in this folder. You will need to update the K8s endpoint and CA for your environment.

You will then need to update the [ConfigMap](go-config.yaml) for your environment. You can then deploy the application with the following. An [example config](config.toml) can be found in this folder.

```
$ kubectl apply -f go-config.yaml
configmap/go created

$ kubectl apply -f go-pod.yaml
pod/go created

$ kubectl apply -f go-service.yaml
service/go created
```

Then verify your pod is running:

```
kubectl get pod go
NAME   READY   STATUS    RESTARTS   AGE
go     1/1     Running   0          16s
```
