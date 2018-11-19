'use strict'

const $rdf = require('rdflib')
const debug = require('./debug').ACL
const HTTPError = require('./http-error')
const fs = require('fs')
const util = require('util')
const aclCheck = require('acl-check')

const DEFAULT_ACL_SUFFIX = '.acl'
const ACL = $rdf.Namespace('http://www.w3.org/ns/auth/acl#')

// An ACLChecker exposes the permissions on a specific resource
class ACLChecker {
  constructor (resource, options = {}) {
    this.resource = resource
    this.host = options.host
    this.origin = options.origin
    this.mapper = options.mapper
    this.root = options.root
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
    let agent = $rdf.sym(user)
    let doc = $rdf.sym(this.resource)
    const kb = $rdf.graph()
    var file = await this.mapper.mapUrlToFile({ url: this.resource })
    var path = file.path
    var filename = path
    var aclText
    const isContainer = path.endsWith('/')

    // If this is an ACL, Control mode must be present for any operations
    if (this.isAcl(path)) {
      modesRequired.push(ACL('Control'))
    } else {
      filename = this.makeAclFilename(path)
    }

    if (!isContainer) {
      try {
        aclText = await this._asyncReadfile(filename)
      } catch (error) {
        if (error.code !== 'ENOENT') {
          throw new HTTPError(500, 'Failed when reading ACL file: ' + error.message)
        }
      }
      if (aclText) {
        const url = await this.mapper.mapFileToUrl({path: filename, hostname: this.host})
        $rdf.parse(aclText, kb, url, 'text/turtle')
        const denied = aclCheck.accessDenied(kb, doc, null, url, agent, modesRequired, $rdf.sym(this.origin), this.trustedOrigins)
        if (denied) {
          this.reject(user, denied) // With various parameters
        }
        return true
      }
      // So, the file didn't have its own ACL or wasn't an ACL file itself, so we prepare for looking up the hierarchy
      path = this.trimPath(path)
      filename = this.makeAclFilename(path)
    }

    var cont = false
    do {
      try {
        aclText = await this._asyncReadfile(filename)
      } catch (error) {
        if (error.code === 'ENOENT') {
          cont = true // Meaning, the ACL file was not found
        } else {
          throw new HTTPError(500, 'Failed to read ACL file when traversing directory: ' + error.message)
        }
      }

      if (cont) {
        path = this.trimPath(path)
        filename = this.makeAclFilename(path)
      }

      if (path === this.root) {
        throw new HTTPError(500, 'Server has been misconfigured: No root ACL')
      }
      // Security valve against infinite loops
      if (path.length < 3) {
        throw new HTTPError(500, 'Server Error: Failed to traverse for ACL files')
      }
    } while (cont)

    // Read the file, reject any errors with 500
    const denied = this.accessDenied('called with parameters for a directory')
    if (denied) {
      this.reject(user, denied) // With various parameters
    }
    return true
  }

  isAcl (resource) {
    return resource.endsWith(this.suffix)
  }

  reject (user, err) {
    console.log(err)
    if (user) {
      throw new HTTPError(403, err)
    } else {
      throw new HTTPError(401, 'Unauthenticated')
    }
  }

  trimPath (path) {
    // TODO: Probably not portable between OSes?
    path = path.substring(0, path.length - 1)
    return path.substring(0, path.lastIndexOf('/') + 1)
  }

  makeAclFilename (path) {
    return path + this.suffix
  }

  _asyncReadfile (filename) {
    return util.promisify(fs.readFile)(filename, 'utf-8')
  }

}

module.exports = ACLChecker
module.exports.DEFAULT_ACL_SUFFIX = DEFAULT_ACL_SUFFIX
