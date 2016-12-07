# Datapower s2i

This project demonstrates how to create an s2i Datapower image to facilitate Datapower deployments in Openshift.

![IBM Datapower](https://avatars3.githubusercontent.com/u/8836442?v=3&s=200 "IBM Datapower")

## create a project 

This is the project win which we will run the below commands, you can use a different project.

```
oc new-project datapower
```

## create the s2i datapower image

This commands will create a build config whose outout will be the s2i-datapower.

```
oc new-build https://github.com/raffaelespazzoli/containers-quickstarts#datapower --context-dir=s2i-datapower --name=s2i-datapower --strategy=docker
```
The s2i-datapower image supports two use cases:

* experimentation 
* immutable

## The experimentation use case

In this use case the user connects to the datapower instance and creates the configurations using the web ui.
The configurations are save in two persistent storage volumes (/drouter/config and /drouter/local)
The expectation is that the configurations can be retrieved from the persistent volumes and use as an input for the s2i-datapower image in the immutable use case.
This is just one possbile approach to creating configuration. Any approach is fine.

to use the image in this mode issue the following commands

```
oc new-app --docker-image=datapower/s2i-datapower -e DATAPOWER_ACCEPT_LICENSE=true -e DATAPOWER_WORKER_THREADS=4 --name=datapower
oc set volume dc/datapower --add -m /drouter/config --name datapower-config -t pvc --claim-name=datapower-config --claim-size=1G
oc set volume dc/datapower --add -m /drouter/local --name datapower-local -t pvc --claim-name=datapower-local --claim-size=1G
oc create route passthrough datapower-svc --service datapower --port=8080
oc create route passthrough datapower-console --service datapower --port=9090
``` 
## The immutable mode

In this mode we assume that the datapower configuration has been created and tested and that we will now use the image without changing the configuration, in line with the immutable infrastructure approach.
To pass the desired configuration to the datapower we will use the s2i process.
The s2i image expects the following structure for injected configuration:

* /src/config will contains the file that need to be in /drouter/config
* /src/local will containe the files that need to be in /drouter/local  

provided that you repo respects this layout you can create a datapower app this way:

```
oc new-app datapower/s2i-datapower~<your-repo> --name=mydatapower
oc create route passthrough mydatapower-svc --service mydatapower --port=8080
```

## examples

To facilitate understanding how this s2i image works, here are some examples

1. protecting an application with datapower via SSO with openshift
2. protecting an application with datapower integrating via LDAP integration
  

## experiment datapower locally
```
docker run --priviliged=true -it -v $PWD/config:/drouter/config -v $PWD/local:/drouter/local -e DATAPOWER_ACCEPT_LICENSE=true -e DATAPOWER_INTERACTIVE=true -p 9090:9090 -p 9022:22 -p 5554:5554 -p 8000-8010:8000-8010 --name idg ibmcom/datapower
```
 


# installing datapower on openshift


```
oc new-build https://github.com/raffaelespazzoli/containers-quickstarts#datapower --context-dir=s2i-datapower --name=s2i-datapower --strategy=docker
oc create service account datapower
oc adm policy add-scc-to-user anyuid -z datapower
oc new-app --docker-image=datapower/s2i-datapower -e DATAPOWER_ACCEPT_LICENSE=true -e DATAPOWER_WORKER_THREADS=4 --name=datapower
oc patch dc/datapower --patch '{"spec":{"template":{"spec":{"serviceAccountName": "datapower"}}}}'
oc set volume dc/datapower --add -m /drouter/config --name datapower-config -t pvc --claim-name=datapower-config --claim-size=1G
oc set volume dc/datapower --add -m /drouter/local --name datapower-local -t pvc --claim-name=datapower-local --claim-size=1G
oc create route passthrough datapower-svc --service datapower --port=8080
oc create route passthrough datapower-console --service datapower --port=9090
```
enabling openshift sso for an application

```
oc create -f ???

```

