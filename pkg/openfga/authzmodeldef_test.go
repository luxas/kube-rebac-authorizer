package openfga_test

const testAuthzModel = `model
  schema 1.1
type user

type group
  relations
    define members: [user, user:*]

type namespace
  relations
    define operates_in: [user, group#members]

type rolebinding
  relations
    define namespaced_assignee: [user, group#members]

type role
  relations
    define namespaced_assignee: [rolebinding#namespaced_assignee]
    define contains: [namespace]
    
    define assignee: namespaced_assignee and operates_in from contains

type resource
  relations
    define anyverb: [role#assignee]
    define get: [role#assignee] or anyverb or get from wildcardmatch
    define list: [role#assignee] or anyverb or list from wildcardmatch
    
    define wildcardmatch: [resource]
`
