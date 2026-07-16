function getScopesForRole(role) {
  if (role === "ADMIN") {
    return [
      "computers:admin",
      "computers:read",
      "batmobile:control",
      "batmobile:status",
      "armory:weapons",
    ];
  }
  return ["computers:read", "batmobile:status"];
}

module.exports = { getScopesForRole };
