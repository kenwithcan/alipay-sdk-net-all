using System;
using System.Xml.Serialization;
using System.Collections.Generic;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayMerchantQipanCrowdCreateModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayMerchantQipanCrowdCreateModel : AopObject
    {
        /// <summary>
        /// 人群描述
        /// </summary>
        [XmlElement("crowd_desc")]
        public string CrowdDesc { get; set; }

        /// <summary>
        /// 人群名称 最大长度为15个字符
        /// </summary>
        [XmlElement("crowd_name")]
        public string CrowdName { get; set; }

        /// <summary>
        /// 商户外部用户人群code 用于标识商家人群，需保证同一商户下crowd_code唯一
        /// </summary>
        [XmlElement("external_crowd_code")]
        public string ExternalCrowdCode { get; set; }

        /// <summary>
        /// 人群包含的用户列表 单次上传用户数上限为1000，若用户量过大可分批通过alipay.merchant.qipan.crowduser.add接口上传
        /// </summary>
        [XmlArray("user_list")]
        [XmlArrayItem("qipan_merchant_crowd_user")]
        public List<QipanMerchantCrowdUser> UserList { get; set; }
    }
}
