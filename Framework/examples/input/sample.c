/*
 * examples/input/sample.c
 *
 * 由 test_data/test_cases.jsonl 注入：PrimeVul 测试用例，共 5 条。
 * 数据集：PrimeVul（函数级漏洞检测基准，来源项目 Chrome）。
 * 注入规则：函数体按数据集原样（verbatim）保留；label / cwe 直接取自数据集字段，
 *           未自行判断“是否属实”。
 *
 * 注意：这些是从 Chrome / ChromeOS 抽取的 C++ 成员函数片段（含 std:: 与类成员访问），
 *       单独放入本文件不保证可独立编译；扫描流程按文本处理（污点分析限制在本文件内）。
 *
 * 用例清单：
 *   #1  id=90104  label=0  cwe=[]  line_count=25  source=Chrome
 *   #2  id=90108  label=0  cwe=[]  line_count=20  source=Chrome
 *   #3  id=90111  label=0  cwe=[]  line_count=24  source=Chrome
 *   #4  id=90112  label=0  cwe=[]  line_count=28  source=Chrome
 *   #5  id=90115  label=0  cwe=[]  line_count=23  source=Chrome
 */

/* ============================ case 1/5 ============================
 * id=90104  label=0  cwe=[]  line_count=25  source=Chrome
 * func: std::string CellularNetwork::ActivationStateToString(ActivationState)
 */
std::string CellularNetwork::ActivationStateToString(
    ActivationState activation_state) {
  switch (activation_state) {
    case ACTIVATION_STATE_ACTIVATED:
      return l10n_util::GetStringUTF8(
          IDS_CHROMEOS_NETWORK_ACTIVATION_STATE_ACTIVATED);
      break;
    case ACTIVATION_STATE_ACTIVATING:
      return l10n_util::GetStringUTF8(
          IDS_CHROMEOS_NETWORK_ACTIVATION_STATE_ACTIVATING);
      break;
    case ACTIVATION_STATE_NOT_ACTIVATED:
      return l10n_util::GetStringUTF8(
          IDS_CHROMEOS_NETWORK_ACTIVATION_STATE_NOT_ACTIVATED);
      break;
    case ACTIVATION_STATE_PARTIALLY_ACTIVATED:
      return l10n_util::GetStringUTF8(
          IDS_CHROMEOS_NETWORK_ACTIVATION_STATE_PARTIALLY_ACTIVATED);
      break;
    default:
      return l10n_util::GetStringUTF8(
          IDS_CHROMEOS_NETWORK_ACTIVATION_STATE_UNKNOWN);
      break;
  }
}

/* ============================ case 2/5 ============================
 * id=90108  label=0  cwe=[]  line_count=20  source=Chrome
 * func: virtual void AddNetworkObserver(const std::string&, NetworkObserver*)
 */
  virtual void AddNetworkObserver(const std::string& service_path,
                                  NetworkObserver* observer) {
    DCHECK(observer);
    if (!EnsureCrosLoaded())
      return;
    NetworkObserverMap::iterator iter = network_observers_.find(service_path);
    NetworkObserverList* oblist;
    if (iter != network_observers_.end()) {
      oblist = iter->second;
    } else {
      std::pair<NetworkObserverMap::iterator, bool> inserted =
        network_observers_.insert(
            std::make_pair<std::string, NetworkObserverList*>(
                service_path,
                new NetworkObserverList(this, service_path)));
      oblist = inserted.first->second;
    }
    if (!oblist->HasObserver(observer))
      oblist->AddObserver(observer);
  }

/* ============================ case 3/5 ============================
 * id=90111  label=0  cwe=[]  line_count=24  source=Chrome
 * func: CellularNetwork::CellularNetwork(const CellularNetwork&)
 */
CellularNetwork::CellularNetwork(const CellularNetwork& network)
    : WirelessNetwork(network) {
  activation_state_ = network.activation_state();
  network_technology_ = network.network_technology();
  roaming_state_ = network.roaming_state();
  restricted_pool_ = network.restricted_pool();
  service_name_ = network.service_name();
  operator_name_ = network.operator_name();
  operator_code_ = network.operator_code();
  payment_url_ = network.payment_url();
  meid_ = network.meid();
  imei_ = network.imei();
  imsi_ = network.imsi();
  esn_ = network.esn();
  mdn_ = network.mdn();
  min_ = network.min();
  model_id_ = network.model_id();
  manufacturer_ = network.manufacturer();
  firmware_revision_ = network.firmware_revision();
  hardware_revision_ = network.hardware_revision();
  last_update_ = network.last_update();
  prl_version_ = network.prl_version();
  type_ = TYPE_CELLULAR;
}

/* ============================ case 4/5 ============================
 * id=90112  label=0  cwe=[]  line_count=28  source=Chrome
 * func: CellularNetwork::CellularNetwork(const ServiceInfo*)
 */
CellularNetwork::CellularNetwork(const ServiceInfo* service)
    : WirelessNetwork(service) {
  service_name_ = SafeString(service->name);
  activation_state_ = service->activation_state;
  network_technology_ = service->network_technology;
  roaming_state_ = service->roaming_state;
  restricted_pool_ = service->restricted_pool;
  if (service->carrier_info) {
    operator_name_ = SafeString(service->carrier_info->operator_name);
    operator_code_ = SafeString(service->carrier_info->operator_code);
    payment_url_ = SafeString(service->carrier_info->payment_url);
  }
  if (service->device_info) {
    meid_ = SafeString(service->device_info->MEID);
    imei_ = SafeString(service->device_info->IMEI);
    imsi_ = SafeString(service->device_info->IMSI);
    esn_ = SafeString(service->device_info->ESN);
    mdn_ = SafeString(service->device_info->MDN);
    min_ = SafeString(service->device_info->MIN);
    model_id_ = SafeString(service->device_info->model_id);
    manufacturer_ = SafeString(service->device_info->manufacturer);
    firmware_revision_ = SafeString(service->device_info->firmware_revision);
    hardware_revision_ = SafeString(service->device_info->hardware_revision);
    last_update_ = SafeString(service->device_info->last_update);
    prl_version_ = service->device_info->PRL_version;
  }
  type_ = TYPE_CELLULAR;
}

/* ============================ case 5/5 ============================
 * id=90115  label=0  cwe=[]  line_count=23  source=Chrome
 * func: void CellularNetwork::Clear()
 */
void CellularNetwork::Clear() {
  WirelessNetwork::Clear();
  activation_state_ = ACTIVATION_STATE_UNKNOWN;
  roaming_state_ = ROAMING_STATE_UNKNOWN;
  network_technology_ = NETWORK_TECHNOLOGY_UNKNOWN;
  restricted_pool_ = false;
  service_name_.clear();
  operator_name_.clear();
  operator_code_.clear();
  payment_url_.clear();
  meid_.clear();
  imei_.clear();
  imsi_.clear();
  esn_.clear();
  mdn_.clear();
  min_.clear();
  model_id_.clear();
  manufacturer_.clear();
  firmware_revision_.clear();
  hardware_revision_.clear();
  last_update_.clear();
  prl_version_ = 0;
}
