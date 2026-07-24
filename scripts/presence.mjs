// A2A §8.4.1 field-presence pre-processing: before JCS, apply proto3
// presence semantics per field class:
//   REQUIRED — always kept, even at the proto default.
//   EXPLICIT — proto3 `optional` scalars, message fields, and oneof variants:
//              kept whenever physically present; presence in JSON means they
//              were explicitly set, even to a default (e.g. "streaming": false,
//              retained in the spec's own §8.4.1 worked example).
//   IMPLICIT — plain scalars, repeated, map: omitted when the value equals the
//              proto default (empty string/array/object, false, 0).
// Field-behavior map derived from a2aproject/A2A specification/grpc/a2a.proto (v1.0).
//
// Unknown fields (e.g. legacy/vendor fields on pre-1.0 cards) are kept as-is:
// their presence in the JSON means they were explicitly set, and dropping
// them would break verification of cards signed over them.

const R = (rule) => ({ presence: 'REQUIRED', ...rule });
const E = (rule) => ({ presence: 'EXPLICIT', ...rule });
const I = (rule) => ({ presence: 'IMPLICIT', ...rule });

// rule: { presence, message?, shape? ('single'|'repeated'|'map'), struct? }
const AGENT_CARD_FIELD_BEHAVIOR = {
  AgentCard: {
    name: R(),
    description: R(),
    supportedInterfaces: R({ message: 'AgentInterface', shape: 'repeated' }),
    provider: E({ message: 'AgentProvider' }),
    version: R(),
    documentationUrl: E(),
    capabilities: R({ message: 'AgentCapabilities' }),
    securitySchemes: I({ message: 'SecurityScheme', shape: 'map' }),
    securityRequirements: I({ message: 'SecurityRequirement', shape: 'repeated' }),
    defaultInputModes: R(),
    defaultOutputModes: R(),
    skills: R({ message: 'AgentSkill', shape: 'repeated' }),
    // signatures is excluded from signing input entirely (§8.4.1 rule 3)
    signatures: I({ shape: 'repeated' }),
    iconUrl: E(),
  },
  AgentInterface: {
    url: R(),
    protocolBinding: R(),
    tenant: I(),
    protocolVersion: R(),
  },
  AgentProvider: {
    url: R(),
    organization: R(),
  },
  AgentCapabilities: {
    streaming: E(),
    pushNotifications: E(),
    extensions: I({ message: 'AgentExtension', shape: 'repeated' }),
    extendedAgentCard: E(),
  },
  AgentExtension: {
    uri: I(),
    description: I(),
    required: I(),
    params: E({ struct: true }),
  },
  AgentSkill: {
    id: R(),
    name: R(),
    description: R(),
    tags: R(),
    examples: I(),
    inputModes: I(),
    outputModes: I(),
    securityRequirements: I({ message: 'SecurityRequirement', shape: 'repeated' }),
  },
  SecurityRequirement: {
    schemes: I({ message: 'StringList', shape: 'map' }),
  },
  StringList: {
    list: I(),
  },
  // SecurityScheme is a oneof — each variant is an explicit-presence message field.
  SecurityScheme: {
    apiKeySecurityScheme: E({ message: 'APIKeySecurityScheme' }),
    httpAuthSecurityScheme: E({ message: 'HTTPAuthSecurityScheme' }),
    oauth2SecurityScheme: E({ message: 'OAuth2SecurityScheme' }),
    openIdConnectSecurityScheme: E({ message: 'OpenIdConnectSecurityScheme' }),
    mtlsSecurityScheme: E({ message: 'MutualTlsSecurityScheme' }),
  },
  APIKeySecurityScheme: {
    description: I(),
    location: R(),
    name: R(),
  },
  HTTPAuthSecurityScheme: {
    description: I(),
    scheme: R(),
    bearerFormat: I(),
  },
  OAuth2SecurityScheme: {
    description: I(),
    flows: R({ message: 'OAuthFlows' }),
    oauth2MetadataUrl: I(),
  },
  OpenIdConnectSecurityScheme: {
    description: I(),
    openIdConnectUrl: R(),
  },
  MutualTlsSecurityScheme: {
    description: I(),
  },
  OAuthFlows: {
    authorizationCode: E({ message: 'AuthorizationCodeOAuthFlow' }),
    clientCredentials: E({ message: 'ClientCredentialsOAuthFlow' }),
    deviceCode: E({ message: 'DeviceCodeOAuthFlow' }),
    implicit: E({ message: 'ImplicitOAuthFlow' }),
    password: E({ message: 'PasswordOAuthFlow' }),
  },
  AuthorizationCodeOAuthFlow: {
    authorizationUrl: R(),
    tokenUrl: R(),
    refreshUrl: I(),
    scopes: R(),
  },
  ClientCredentialsOAuthFlow: {
    tokenUrl: R(),
    refreshUrl: I(),
    scopes: R(),
  },
  DeviceCodeOAuthFlow: {
    deviceAuthorizationUrl: R(),
    tokenUrl: R(),
    refreshUrl: I(),
    scopes: R(),
  },
  ImplicitOAuthFlow: {
    authorizationUrl: I(),
    refreshUrl: I(),
    scopes: I(),
  },
  PasswordOAuthFlow: {
    tokenUrl: I(),
    refreshUrl: I(),
    scopes: I(),
  },
};

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

const isProtoDefault = (v) =>
  v === undefined ||
  v === null ||
  v === '' ||
  v === false ||
  v === 0 ||
  (Array.isArray(v) && v.length === 0) ||
  (isPlainObject(v) && Object.keys(v).length === 0);

function processValue(value, rule) {
  if (rule.struct || !rule.message) return value;
  const shape = rule.shape ?? 'single';
  if (shape === 'repeated' && Array.isArray(value)) {
    return value.map((item) => (isPlainObject(item) ? processMessage(item, rule.message) : item));
  }
  if (shape === 'map' && isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, isPlainObject(v) ? processMessage(v, rule.message) : v])
    );
  }
  if (shape === 'single' && isPlainObject(value)) {
    return processMessage(value, rule.message);
  }
  return value;
}

function processMessage(obj, messageName) {
  const spec = AGENT_CARD_FIELD_BEHAVIOR[messageName];
  const out = {};
  for (const [key, raw] of Object.entries(obj)) {
    if (raw === undefined) continue;
    const rule = spec?.[key];
    if (!rule) {
      // Unknown field — keep verbatim (spec §5.7: implementations ignore unknowns)
      out[key] = raw;
      continue;
    }
    const value = processValue(raw, rule);
    if (rule.presence === 'IMPLICIT' && isProtoDefault(value)) continue;
    out[key] = value;
  }
  return out;
}

// §8.4 signing payload: presence-processed card minus its signatures field.
export function cardSigningPayload(card) {
  const { signatures: _omit, ...unsigned } = card;
  return processMessage(unsigned, 'AgentCard');
}
