class OfflineProvider {
  id() {
    return "agentforge:offline-fixture";
  }

  async callApi() {
    return { output: "REFUSED_OFFLINE_FIXTURE" };
  }
}

module.exports = OfflineProvider;
