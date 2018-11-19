'use strict'

const $rdf = require('rdflib')
const debug = require('./debug').ACL
// const HTTPError = require('./http-error')
const fs = require('fs')
const util = require('util')

const DEFAULT_ACL_SUFFIX = '.acl'
const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')

// An ACLChecker exposes the permissions on a specific resource
class ACLChecker {
  constructor (resource, options = {}) {
    this.resource = resource
    this.host = options.host
    this.origin = options.origin
    this.mapper = options.mapper
    this.fetch = options.fetch
    this.fetchGraph = options.fetchGraph
    this.strictOrigin = options.strictOrigin
    this.trustedOrigins = options.trustedOrigins
    this.suffix = options.suffix || DEFAULT_ACL_SUFFIX
  }

  // Returns a fulfilled promise when the user can access the resource
  // in the given mode, or rejects with an HTTP error otherwise
  async can (user, mode) {
    debug('Checking permissions for ' + this.resource)
    let modesRequired = [ ACL(mode) ]
    var path = this.mapper.mapUrlToFile({ url: this.resource })
    var filename = path
    var aclText
    const isContainer = path.endsWith('/')

    // If this is an ACL, Control mode must be present for any operations
    if (this.isAcl(this.resource)) {
      modesRequired.push(ACL('Control'))
    } else {
      filename = makeAclFilename(path)
    }

    if (!isContainer) {
      try {
        aclText = await _asyncReadfile(filename)
      } catch (error) {
        if (error !== 'ENOENT') {
          reject('Parse error')
        }
      }
      if (aclText) {
        const denied = accessDenied('called with parameters for a file')
        if (denied) {
          reject(denied) // With various parameters
        }
        return true
      }
      // So, the file didn't have its own ACL or wasn't an ACL file itself, so we prepare for looking up the hierarchy
      path = trimPath(path)
      filename = makeAclFilename(path)
    }

    var cont = false
    do {
      try {
        aclText = await _asyncReadfile(filename)
      } catch (error) {
        if (error === 'ENOENT') {
          cont = true // Meaning, the ACL file was not found
        } else {
          reject('A 500 of some sort')
        }
      }

      if (cont) {
        path = trimPath(path)
        filename = makeAclFilename(path)
      }
      if (path === root) {
        reject('Server has been misconfigured: No root ACL') // various other parameters
      }
      // Danger: Handle the possibility no ACL is found and path === root is never true for some reason
    } while (cont)

    // Read the file, reject any errors with 500
    const denied = accessDenied('called with parameters for a directory')
    if (denied) {
      reject(denied) // With various parameters
    }
    return true
  }

}

function accessDenied (msg) {
  console.log(msg)
}

function reject (err) {
  console.log(err)
  // Rejections can be 401, 403 or 500
}

function trimPath (path) {
  return path.substring(path.lastIndexOf('/'))
}

function makeAclFilename (path) {
  return path + this.suffix
}

/* function isAcl (resource) {
  return resource.endsWith(this.suffix)
} */

function _asyncReadfile (filename) {
  return util.promisify(fs.readFile)(filename, 'utf-8')
}

module.exports = ACLChecker
module.exports.DEFAULT_ACL_SUFFIX = DEFAULT_ACL_SUFFIX
