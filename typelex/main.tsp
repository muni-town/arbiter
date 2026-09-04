import "@typelex/emitter";
import "./externals.tsp";

/** Alias for a totally open union, requiring the record to be an object with a `$type` field. */
alias OpenUnion = unknown | never;

namespace town.muni.arbiter.defs {
  @inline
  @maxLength(1024)
  scalar SpaceKey extends string;
  
  /**
   * The maximum depth to allow when doing remote resolutions.
   * 
   * Because spaces are allowed to have members resolved from remote spaces,
   * all of the arbiter endpoints have an optional resolution depth parameter
   * that can be used to limit how many chained remote calls can be resolved.
   * 
   * This applies both to queries and procedures. Queries may need to resolve
   * external members to complete the member list, and procedures may need
   * to resolve external members if the requesting member is not in the local
   * member list, to see if the member has access through a remote list.
   */
  @inline
  @minValue(0)
  scalar ResolverDepth extends integer;

  @inline union Member {
    MemberDid,
    MemberLocalSpace,
    MemberRemoteSpace,
  }

  /** A member specified directly by their DID. */
  model MemberDid {
    /** The DID of the member. */
    @required did: did,
  }

  /** A member representing all of the members of another space that is on this arbiter. */
  model MemberLocalSpace {
    /** The key of the space on this arbiter. */
    @required spaceKey: SpaceKey,
  }

  /** A member representing all of the members of another space on another arbiter. */
  model MemberRemoteSpace {
    /** The DID of the remote arbiter. */
    @required arbiterDid: did,
    /** The key of the space on the remote arbiter. */
    @required spaceKey: SpaceKey,
  }

  /** The specified DID already has an arbiter for it on this server. */
  model ErrArbiterAlreadyExists {}

  /** The requesting user is not allowed to make the request. */
  model ErrPermissionDenied {}

  /** A policy failed to compile, a config input was invalid, or a pipeline-referenced policy record is missing or malformed. */
  model ErrInvalidPolicy {}

  /**
   * The config was changed by another request during the execution of this request.
   * 
   * The action should be retried if still applicable.
   * */
  model ErrRaceCondition {}

  /**
   * The config lexicon provided is not supported by this server. Different servers
   * may support different config lexicons.
   * */
  model ErrUnsupportedConfigLexicon {}

  /**
   * The config provided is invalid for some reason other than it being an unsupported
   * lexicon.
   */
  model ErrInvalidConfig {}

  /** The specified arbiter does not exist on this server. */
  model ErrArbiterNotExists {}

  /** The specified space already exists on this arbiter. */
  model ErrSpaceExists {}

  /** The specified space does not exist on this arbiter. */
  model ErrSpaceNotExists {}

  /** The specified member is not in the space. */
  model ErrMemberNotInSpace {}

  /** The specified DID is not managed by this service. */
  model ErrDidNotManaged {}

  /** 
   * This error is thrown when you try to create an arbiter for an existing DID, but
   * The DID doc does not have an arbiter record pointing to this server.
   */
  model ErrDidDocNotPointingToThisArbiter {}

  /**
   * A service endpoint entry within a DID document's `services` field.
   *
   * Maps a service ID (e.g. `atproto_pds`) to its type and URL.
   * Per the DID PLC spec, the service ID should not include a `#` prefix;
   * the `#` will be added when rendering the DID document.
   */
  model ServiceEndpoint {
    /** The type of the service (e.g. `AtprotoPersonalDataServer`). */
    @required type: string,
    /** The endpoint URL (e.g. `https://pds.example.com`). */
    @required endpoint: string,
  }

  /**
   * Configurable fields for a DID PLC document.
   */
  model DidDocConfig {
    /**
     * Priority-ordered list of public keys in `did:key` encoding.
     * At least 1 and at most 5 keys, with no duplication.
     * These keys control the DID identifier (can sign rotation operations).
     */
    @required rotationKeys: string[],
    /**
     * Map from verification method ID to public key in `did:key` encoding.
     * The ID should not include a `#` prefix; it will be added when rendering
     * the DID document. These keys do **not** have control over the DID.
     */
    @required verificationMethods: unknown,
    /**
     * Priority-ordered list of URIs indicating other names or aliases
     * associated with the DID. For atproto, this should include an `at://`
     * URI for the account's handle.
     */
    @required alsoKnownAs: string[],
    /**
     * Map from service ID to service endpoint configuration.
     * The ID should not include a `#` prefix; it will be added when rendering
     * the DID document.
     */
    @required services: unknown,
  }
}

namespace town.muni.arbiter.createArbiter {
  /**
   * Create a new arbiter.
   * 
   * The return type is an open union that will contain a `$type` key and may be
   * different depending on the server and/or the provided config `$type`.
   * */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterAlreadyExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrUnsupportedConfigLexicon,
    town.muni.arbiter.defs.ErrInvalidConfig,
  )
  op main(
    @required input: {
      /**
       * The DID of the arbiter.
       * 
       * Different servers may have different policies regarding who is allowed
       * to create an arbiter for what DIDs.
       * 
       * The DID will not be created by this procedure: it must be created
       * separately and have its #space_host service pointed to this server.
       */
      @required arbiterDid: did;
      /**
       * A configuration object for the arbiter.
       * 
       * Different servers will support different config lexicons. The NSID of
       * the config lexicon determines what kind of arbiter it is. Different
       * kinds of arbiters may have totally different mechanisms for determining
       * access.
       */
      @required config: OpenUnion
    },
  ): OpenUnion;
}

namespace town.muni.arbiter.createAppPasswordArbiter {
  /**
   * Create a new arbiter backed by a PDS app password.
   *
   * This creates an arbiter with credentials for an AT Protocol PDS account
   * that will be used to proxy XRPC requests during policy evaluation.
   */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterAlreadyExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrUnsupportedConfigLexicon,
    town.muni.arbiter.defs.ErrInvalidConfig,
    town.muni.arbiter.defs.ErrDidDocNotPointingToThisArbiter,
  )
  op main(
    @required input: {
      /**
       * The DID of the arbiter.
       */
      @required arbiterDid: did;
      /**
       * If set to `true` this will replace an existing arbiter for the
       * same DID without erroring, if one exists.
       * 
       * The old configuration WILL BE LOST.
       */
      replaceExisting?: boolean;
      /**
       * The app password for the PDS account.
       */
      @required appPassword: string;
      /**
       * A configuration object for the arbiter.
       *
       * Different servers will support different config lexicons. The NSID of
       * the config lexicon determines what kind of arbiter it is. Different
       * kinds of arbiters may have totally different mechanisms for determining
       * access.
       */
      @required config: OpenUnion,
    },
  ): OpenUnion;
}

namespace town.muni.arbiter.deleteArbiter {
  /** Delete an arbiter from the server. */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    @required input: {
      // The DID of the arbiter to delete.
      @required arbiterDid: did,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.setArbiterConfig {
  /** Set the config object for an arbiter. */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrInvalidConfig,
    town.muni.arbiter.defs.ErrUnsupportedConfigLexicon,
  )
  op main(
    @required input: {
      /** The DID of the arbiter to set the config for. */
      @required arbiterDid: did,
      /** 
       * The config object.
       * 
       * Different server's will support different config NSIDs, and most-likely servers
       * will not allow you to change the NSID after creation, even if they support
       * updating the config.
       */
      @required config: OpenUnion,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.getArbiterConfig {
  /** Get the current config object for an arbiter. */
  @query
  @errors(town.muni.arbiter.defs.ErrPermissionDenied)
  op main(
    /** The DID of the arbiter to fetch the config from */
    @required arbiterDid: did;
    resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
  ): {
    @required config: OpenUnion
  };
}

namespace town.muni.arbiter.createSpace {
  /** Create a new space on an arbiter. */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrRaceCondition,
  )
  op main(
    @required input: {
      /** The DID of the arbiter to create the space in. */
      @required arbiterDid: did,
      /** The NSID of the space type. */
      @required spaceType: nsid,
      /** The key of the space to create. */
      @required spaceKey: town.muni.arbiter.defs.SpaceKey,
      /**
       * The space configuration.
       * 
       * Different servers will support different space config lexicons. Which
       * lexicons are supported will also likely depend on the arbiter's config type.
       */
      @required config: OpenUnion,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.deleteSpace {
  /** Delete a space from the arbiter. */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrSpaceNotExists,
  )
  op main(
    @required input: {
      /** The DID of the arbiter to delete the space from. */
      @required arbiterDid: did,
      /** The space type of the spc */
      @required spaceType: nsid,
      /** The space key of the space to delete. */
      @required spaceKey: town.muni.arbiter.defs.SpaceKey,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.setSpaceConfig {
  /** Configure a space on the arbiter. */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrRaceCondition,
  )
  op main(
    @required input: {
      /** The DID of the arbiter that the space is in. */
      @required arbiterDid: did,
      /** The key of the space to configure. */
      @required spaceKey: town.muni.arbiter.defs.SpaceKey,
      /** The type of the space to configure. */
      @required spaceType: nsid,
      /** If provided sets a new type for the space. */
      newSpaceType?: nsid,
      /** The new space configuration. */
      @required config: OpenUnion,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.getSpaceConfig {
  /** Get the configuration of a space on the arbiter. */
  @query
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    /** The DID of the arbiter that the space is in. */
    @required arbiterDid: did,
    /** The type of the space. */
    @required spaceType: nsid,
    /** The key of the space. */
    @required spaceKey: town.muni.arbiter.defs.SpaceKey,
    resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
  ): {
    /** The type of the space. */
    @required spaceType: nsid,
    /** The space configuration object. */
    @required config: OpenUnion,
  };
}

namespace town.muni.arbiter.getSpaceMembers {
  /**
   * Get the members that have been assigned to the space.
   * 
   * This is not a flat membership list, but a list of the direct members
   * of the space, including DIDs, local spaces, and remote spaces that have
   * been added as members, without doing any resolution of remote spaces.
   * */
  /** An entry describing a member and their access config. */
  model SpaceMemberEntry {
    /** The member ID */
    @required member: town.muni.arbiter.defs.Member,
    /** The member's access config object. */
    @required access: OpenUnion,
  }

  @query
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    /** The DID of the arbiter that the space is in. */
    @required arbiterDid: did,
    /** The type of the space. */
    @required spaceType: nsid,
    /** The key of the space. */
    @required spaceKey: town.muni.arbiter.defs.SpaceKey,
    resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
  ): {
    /** The members of the space */
    @required members: SpaceMemberEntry[],
  };
}

namespace town.muni.arbiter.setSpaceMemberAccess {
  /**
   * Set the access of a member in a space.
   * 
   * This is also how you add a new member to the space.
   * */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrRaceCondition,
    town.muni.arbiter.defs.ErrMemberNotInSpace,
    town.muni.arbiter.defs.ErrInvalidConfig,
  )
  op main(
    @required input: {
      /** The DID of the arbiter that the space is in. */
      @required arbiterDid: did,
      /** The type of the space. */
      @required spaceType: nsid,
      /** The key of the space. */
      @required spaceKey: town.muni.arbiter.defs.SpaceKey,
      /** The member to set the access of. */
      @required member: town.muni.arbiter.defs.Member,
      /** The updated access configuration for the member. */
      @required access: OpenUnion,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.removeSpaceMember {
  /**
   * Remove a member's access from a space.
   * */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrRaceCondition,
    town.muni.arbiter.defs.ErrMemberNotInSpace,
  )
  op main(
    @required input: {
      /** The DID of the arbiter that the space is in. */
      @required arbiterDid: did,
      /** The type of the space. */
      @required spaceType: nsid,
      /** The key of the space. */
      @required spaceKey: town.muni.arbiter.defs.SpaceKey,
      /** The member to set the access of. */
      @required member: town.muni.arbiter.defs.Member,
      /** The updated access configuration for the member. */
      @required access: OpenUnion,
      resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
    }
  ): OpenUnion;
}

namespace town.muni.arbiter.resolveSpaceMembers {
  /**
   * Get the flattened, resolved list of members for a space.
   * 
   * This member list will be the same as what the server is expected to return
   * as the space host, but it will additionally contain a member config
   * object for each member.
   * 
   * The details of the member config object are dependent on the server implementation
   * and possibly the arbiter config type.
   * */
  /** A resolved member entry with DID and access config. */
  model ResolvedMember {
    /** The member DID. */
    @required did: did,
    /** The member's access config object. */
    @required access: OpenUnion,
  }

  /** A remote space that could not be resolved. */
  model MissingSpace {
    /** The space that could not be resolved. */
    @required space: town.muni.arbiter.defs.MemberRemoteSpace,
    /** The access object of the space that could not be resolved. */
    @required access: OpenUnion,
  }

  @query
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    /** The DID of the arbiter that the space is in. */
    @required arbiterDid: did,
    /** The type of the space. */
    @required spaceType: nsid,
    /** The key of the space. */
    @required spaceKey: town.muni.arbiter.defs.SpaceKey,
    resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
  ): {
    /** The members of the space */
    @required members: ResolvedMember[],
    /** 
     * Contains the list of remote spaces that could not be resolved.
     * 
     * If the hosts of remote spaces time out, then the server will reply with all
     * of the members that it was able to resolve and will list the spaces that
     * could not be resolved in `missingSpaces`.
     * */
    @required missingSpaces: MissingSpace[],
  };
}

namespace town.muni.arbiter.listSpaces {
  /**
   * Get the members that have been assigned to the space.
   * 
   * This is not a flat membership list, but a list of the direct members
   * of the space, including DIDs, local spaces, and remote spaces that have
   * been added as members, without doing any resolution of remote spaces.
   * */
  /** A space entry containing key, type and optional config. */
  model SpaceEntry {
    /** The space's key. */
    @required spaceKey: town.muni.arbiter.defs.SpaceKey,
    /** The type of the space. */
    @required spaceType: nsid,
    /**
     * The space config.
     * 
     * This may not be returned if the server does not want to allow the requesting user
     * to read it.
     * */
    config?: OpenUnion,
  }

  @query
  @errors(
    town.muni.arbiter.defs.ErrArbiterNotExists,
    town.muni.arbiter.defs.ErrSpaceNotExists,
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    /** The DID of the arbiter that the space is in. */
    @required arbiterDid: did,
    resolverDepth?: town.muni.arbiter.defs.ResolverDepth,
  ): {
    /** The list of spaces on the arbiter that the requesting user has access to. */
    @required spaces: SpaceEntry[],
  };
}

namespace town.muni.arbiter.createDid {
  /**
   * Create a new DID that will be managed by this service.
   * 
   * A new arbiter will be created in order to manage access
   * to the DID. The arbiter will be configured with a default
   * policy that sets the creator as the owner of the arbiter
   * and allows them to change the DID document.
   *
   * The policy can also be changed later.
   *
   * The created DID will be returned
   * */
  @procedure
  op main(): {
    @required did: did,
  };
}

namespace town.muni.arbiter.updateDidDoc {
  /**
   * Update the DID doc for a DID that is hosted by this service.
   * */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrDidNotManaged,
    town.muni.arbiter.defs.ErrPermissionDenied,
  )
  op main(
    @required input: {
      /** The DID to update the document for. */
      @required did: did,
      /** Updated DID document configuration. */
      @required config: town.muni.arbiter.defs.DidDocConfig,
    }
  ): {
    @required did: did,
  };
}

namespace town.muni.arbiter.config {
  /**
   * Trusted scopes and policy pipeline configuration for a stewarded
   * arbiter.
   *
   * One record per arbiter (rkey `self`) in the stewarded account's repo,
   * maintained by `town.muni.arbiter.installPolicy` appends, wholesale
   * `town.muni.arbiter.resetConfig` rewrites, and direct repo writes, and
   * hot-reloaded over Jetstream. `trustedScopes` gates which
   * `*.arbiter.proxy` scopes the arbiter accepts at all; `policyLayers` is the
   * ordered community policy pipeline evaluated after the scope gate.
   */
  @rec("literal:self")
  model Main {
    /**
     * NSID scopes (e.g. `community.lexicon.authCalendar`) this arbiter
     * accepts. A scoped proxy request's scope — its NSID with the
     * `.arbiter.proxy` suffix stripped — must be exactly one of these
     * entries; anything else is rejected before the policy pipeline runs.
     */
    @required trustedScopes: string[],
    /**
     * Ordered `at://` URIs of `town.muni.arbiter.policy` records (or
     * same-shaped records in other repos) forming the community policy
     * pipeline. Evaluated in order: `pass` defers to the next layer, the first
     * layer that handles or denies wins, and falling off the end denies.
     */
    @required policyLayers: string[],
  }
}

namespace town.muni.arbiter.policy {
  /**
   * A named Rego policy in a stewarded arbiter's policy pipeline.
   *
   * The rkey is the policy name; referenced from
   * `town.muni.arbiter.config/self`'s `policyLayers` as
   * `at://<did>/town.muni.arbiter.policy/<rkey>`. Remote (app-owned) shared
   * policies use the same record shape in another repo.
   */
  @rec("any")
  model Main {
    /** Rego source text for the policy. */
    @required policy: string,
  }
}

namespace town.muni.arbiter.recovery {
  /**
   * Recovery-admin designation record for a stewarded arbiter.
   *
   * This record is the source of truth for who may recover the arbiter: the
   * arbiter server re-reads it on every `town.muni.arbiter.installPolicy`
   * call, and rewriting it rotates the recovery admin with effect on the
   * next call. Written by the arbiter server at provisioning/import time
   * (the provisioning caller) and re-written by it when repairing a
   * half-provisioned account.
   */
  @rec("literal:self")
  model Main {
    /**
     * The DID of the account's designated recovery admin — the only account
     * that may install policies via `town.muni.arbiter.installPolicy` (until
     * the record is rewritten).
     */
    @required did: did,
  }
}

namespace town.muni.arbiter.installPolicy {
  /**
   * Append a policy layer and/or trusted scopes to a stewarded arbiter's
   * community policy configuration.
   *
   * The caller authenticates via serviceAuth (aud = arbiter-server DID,
   * lxm = town.muni.arbiter.installPolicy). The request is approved one of
   * two ways:
   *
   * 1. Recovery-admin bypass: the caller is the DID designated in the
   *    arbiter's `town.muni.arbiter.recovery/self` record. The record is
   *    re-read from the repo on every call, so rewriting it rotates the
   *    recovery admin with effect on the next installPolicy call. This path
   *    bypasses the pipeline and works even while the arbiter is offboarded
   *    (the bootstrap path: provisioning/import writes the record naming the
   *    caller, so the very first install always comes from the recovery
   *    admin).
   *
   * 2. Community pipeline: any other caller's install request is evaluated
   *    by the arbiter's installed policy pipeline (the pipeline sees the
   *    request with nsid `town.muni.arbiter.installPolicy`). A layer may
   *    deny the install, answer it itself, or approve it by completing with
   *    `{ "handleBuiltin": true }`, which hands the request to this
   *    endpoint's built-in handler to perform the install. Falling off the
   *    end of the pipeline denies (fail-closed). The arbiter must be online
   *    for this path; if it is offboarded the request is denied and the
   *    recovery admin should use `town.muni.arbiter.resetConfig` to restore
   *    it.
   *
   * Semantics — append only. The referenced policy layer is appended at the
   * END of the arbiter's policy layers (lowest priority: an appended layer only
   * sees requests the community's existing layers pass), and the trusted
   * scopes are unioned into the existing set (already-present entries keep
   * their position, new ones are appended, duplicates are dropped). Nothing
   * already installed is ever removed or reordered. Re-installing a policy
   * whose at:// URI is already in the pipeline does not duplicate it or
   * elevate its priority: its position is kept, and updated behavior comes
   * from updating the referenced record in its own repo (the update
   * propagates over Jetstream to every arbiter referencing it). When the
   * request would change nothing, the config record is not rewritten.
   *
   * This endpoint never writes policy records: `policy` must reference an
   * existing `town.muni.arbiter.policy` record (in any repo — the caller's
   * own, the stewarded account's, or a shared app-owned one) that the
   * caller wrote beforehand, and it must compile. When the merged scopes or
   * policy layers differ from the current ones, they are written to
   * `town.muni.arbiter.config/self` in the stewarded account's repo
   * (putRecord with swapCommit CAS), then the arbiter is re-onboarded.
   *
   * If no recovery admin is designated in the record, or the account is
   * not stewarded by this server, this endpoint is unavailable (forbidden).
   */
  @procedure
  @errors(
    town.muni.arbiter.defs.ErrPermissionDenied,
    town.muni.arbiter.defs.ErrInvalidPolicy,
  )
  op main(
    @required input: {
      /** The stewarded account whose policy layers to append to. */
      @required arbiterDid: did,
      /**
       * At-uri of a `town.muni.arbiter.policy` record to append to the
       * arbiter's policy layers as their last (lowest-priority) layer. The record may live in
       * any repo (the caller's own, the stewarded account's, or a shared
       * app-owned one), must already exist, carry a string `policy` field,
       * and compile. Must be shaped
       * `at://<did>/town.muni.arbiter.policy/<rkey>`. This endpoint never
       * writes policy records. Omit to change trusted scopes only.
       */
      policy?: string,
      /**
       * NSID scopes (e.g. `community.lexicon.authCalendar`) the arbiter
       * accepts, unioned into the existing set: entries already trusted
       * keep their position, new ones are appended, duplicates are
       * dropped. Required; may be empty (a policy-only or no-op install).
       * A scoped proxy request's scope — its NSID with the
       * `.arbiter.proxy` suffix stripped — must be exactly one of the
       * resulting entries.
       */
      @required trustedScopes: string[],
    }
  ): {
    @required ok: boolean
  };
}
namespace town.muni.arbiter.resetConfig {
  /**
   * Recovery hatch: replace a stewarded arbiter's configuration record
   * wholesale.
   *
   * The caller authenticates via serviceAuth (aud = arbiter-server DID,
   * lxm = town.muni.arbiter.resetConfig). Only the account designated in
   * the arbiter's `town.muni.arbiter.recovery/self` record (the recovery
   * admin) may reset; the record is re-read from the repo on every call, so
   * rewriting it rotates the recovery admin with effect on the next call.
   *
   * This endpoint never evaluates the policy pipeline and works while the
   * arbiter is offboarded (a broken config is exactly what it repairs): the
   * `town.muni.arbiter.config/self` record is replaced verbatim (putRecord
   * with swap_commit CAS, the same machinery as installPolicy) and the
   * arbiter is re-onboarded. The body is shape-validated only — no pipeline
   * compile checks and no record-existence checks: if the new config also
   * fails to load, reset again.
   */
  @procedure
  @errors(town.muni.arbiter.defs.ErrPermissionDenied)
  op main(
    @required input: {
      /** The stewarded account whose configuration to replace. */
      @required arbiterDid: did,
      /**
       * NSID scopes (e.g. `community.lexicon.authCalendar`) the arbiter
       * accepts. A scoped proxy request's scope — its NSID with the
       * `.arbiter.proxy` suffix stripped — must be exactly one of these
       * entries. Written to the arbiter's `town.muni.arbiter.config/self`
       * record verbatim.
       */
      @required trustedScopes: string[],
      /**
       * Ordered `at://` URIs of `town.muni.arbiter.policy` records forming
       * the policy layers. Written to the arbiter's
       * `town.muni.arbiter.config/self` record verbatim; entries are not
       * validated beyond their shape — if the new config fails to load,
       * reset again.
       */
      @required policyLayers: string[],
    }
  ): {
    @required ok: boolean
  };
}

