using System;
using System.Xml.Serialization;
using System.Collections.Generic;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayOfflineProviderCollaborateDevicebindApplyModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayOfflineProviderCollaborateDevicebindApplyModel : AopObject
    {
        /// <summary>
        /// 1. 直联商家三绑定必传： RECORDS_TYPE_PID(直连 PID)、 RECORDS_TYPE_SHOPID(shopid); 2. 可用绑定必传： RECORDS_TYPE_SMID（二级商家 ID） RECORDS_TYPE_PID(PID)。
        /// </summary>
        [XmlArray("device_record_files")]
        [XmlArrayItem("device_record_info")]
        public List<DeviceRecordInfo> DeviceRecordFiles { get; set; }

        /// <summary>
        /// 设备序列号
        /// </summary>
        [XmlElement("device_sn")]
        public string DeviceSn { get; set; }

        /// <summary>
        /// 填写商家在服务商系统内身份资料
        /// </summary>
        [XmlElement("ext_params")]
        public DeviceExtAttribute ExtParams { get; set; }

        /// <summary>
        /// 外部唯一单据号，用来做幂等，标志着唯一的一次设备绑定申请
        /// </summary>
        [XmlElement("out_biz_no")]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 设备绑定场景 IOT_DEVICE_RECORDS_G3_DIRECT(直连三绑定) IOT_DEVICE_RECORDS_G2(可用绑定)
        /// </summary>
        [XmlElement("scene_code")]
        public string SceneCode { get; set; }
    }
}
