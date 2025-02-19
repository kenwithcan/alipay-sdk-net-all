/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// AlipayCommerceIotSdarttoolMessageSendModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceIotSdarttoolMessageSendModel")]
    public partial class AlipayCommerceIotSdarttoolMessageSendModel : IEquatable<AlipayCommerceIotSdarttoolMessageSendModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceIotSdarttoolMessageSendModel" /> class.
        /// </summary>
        /// <param name="biDa">消息是否必达(immediate_msg为false时此字段设置有效)，消息过期时间顺延3*24h. 建议使用expire_time设置消息过期时间.</param>
        /// <param name="deviceQueryType">设备查询条件类型 ；SUPPLIERID_SN:supplierid+sn ;  ITEMID_SN:itemid + sn; SN:sn.</param>
        /// <param name="immediateMsg">是否即时消息; true-校验设备是否在线，false-不校验设备是否在线.</param>
        /// <param name="itemId">产品ID.</param>
        /// <param name="msgContent">消息内容.</param>
        /// <param name="msgContentType">消息内容格式.</param>
        /// <param name="msgExpire">消息过期时间戳(ms)， 默认为当前时间顺延24h有效。当设备在线时消息服务过期之前尝试推送。最大过期时间顺延3*24h.</param>
        /// <param name="msgPriority">消息优先级（immediate_msg为false此字段设置有效）数字越大优先发送。.</param>
        /// <param name="msgType">消息类型： xpaas_common-小程序消息； ruyi_ordermsg-如意订单消息.</param>
        /// <param name="serviceId">服务ID，当小程序消费消息时必传(传入的是小程序ID).</param>
        /// <param name="sn">设备sn号.</param>
        /// <param name="supplierId">厂商ID.</param>
        public AlipayCommerceIotSdarttoolMessageSendModel(bool biDa = default(bool), string deviceQueryType = default(string), bool immediateMsg = default(bool), string itemId = default(string), string msgContent = default(string), string msgContentType = default(string), int msgExpire = default(int), int msgPriority = default(int), string msgType = default(string), string serviceId = default(string), string sn = default(string), string supplierId = default(string))
        {
            this.BiDa = biDa;
            this.DeviceQueryType = deviceQueryType;
            this.ImmediateMsg = immediateMsg;
            this.ItemId = itemId;
            this.MsgContent = msgContent;
            this.MsgContentType = msgContentType;
            this.MsgExpire = msgExpire;
            this.MsgPriority = msgPriority;
            this.MsgType = msgType;
            this.ServiceId = serviceId;
            this.Sn = sn;
            this.SupplierId = supplierId;
        }

        /// <summary>
        /// 消息是否必达(immediate_msg为false时此字段设置有效)，消息过期时间顺延3*24h. 建议使用expire_time设置消息过期时间
        /// </summary>
        /// <value>消息是否必达(immediate_msg为false时此字段设置有效)，消息过期时间顺延3*24h. 建议使用expire_time设置消息过期时间</value>
        [DataMember(Name = "bi_da", EmitDefaultValue = true)]
        public bool BiDa { get; set; }

        /// <summary>
        /// 设备查询条件类型 ；SUPPLIERID_SN:supplierid+sn ;  ITEMID_SN:itemid + sn; SN:sn
        /// </summary>
        /// <value>设备查询条件类型 ；SUPPLIERID_SN:supplierid+sn ;  ITEMID_SN:itemid + sn; SN:sn</value>
        [DataMember(Name = "device_query_type", EmitDefaultValue = false)]
        public string DeviceQueryType { get; set; }

        /// <summary>
        /// 是否即时消息; true-校验设备是否在线，false-不校验设备是否在线
        /// </summary>
        /// <value>是否即时消息; true-校验设备是否在线，false-不校验设备是否在线</value>
        [DataMember(Name = "immediate_msg", EmitDefaultValue = true)]
        public bool ImmediateMsg { get; set; }

        /// <summary>
        /// 产品ID
        /// </summary>
        /// <value>产品ID</value>
        [DataMember(Name = "item_id", EmitDefaultValue = false)]
        public string ItemId { get; set; }

        /// <summary>
        /// 消息内容
        /// </summary>
        /// <value>消息内容</value>
        [DataMember(Name = "msg_content", EmitDefaultValue = false)]
        public string MsgContent { get; set; }

        /// <summary>
        /// 消息内容格式
        /// </summary>
        /// <value>消息内容格式</value>
        [DataMember(Name = "msg_content_type", EmitDefaultValue = false)]
        public string MsgContentType { get; set; }

        /// <summary>
        /// 消息过期时间戳(ms)， 默认为当前时间顺延24h有效。当设备在线时消息服务过期之前尝试推送。最大过期时间顺延3*24h
        /// </summary>
        /// <value>消息过期时间戳(ms)， 默认为当前时间顺延24h有效。当设备在线时消息服务过期之前尝试推送。最大过期时间顺延3*24h</value>
        [DataMember(Name = "msg_expire", EmitDefaultValue = false)]
        public int MsgExpire { get; set; }

        /// <summary>
        /// 消息优先级（immediate_msg为false此字段设置有效）数字越大优先发送。
        /// </summary>
        /// <value>消息优先级（immediate_msg为false此字段设置有效）数字越大优先发送。</value>
        [DataMember(Name = "msg_priority", EmitDefaultValue = false)]
        public int MsgPriority { get; set; }

        /// <summary>
        /// 消息类型： xpaas_common-小程序消息； ruyi_ordermsg-如意订单消息
        /// </summary>
        /// <value>消息类型： xpaas_common-小程序消息； ruyi_ordermsg-如意订单消息</value>
        [DataMember(Name = "msg_type", EmitDefaultValue = false)]
        public string MsgType { get; set; }

        /// <summary>
        /// 服务ID，当小程序消费消息时必传(传入的是小程序ID)
        /// </summary>
        /// <value>服务ID，当小程序消费消息时必传(传入的是小程序ID)</value>
        [DataMember(Name = "service_id", EmitDefaultValue = false)]
        public string ServiceId { get; set; }

        /// <summary>
        /// 设备sn号
        /// </summary>
        /// <value>设备sn号</value>
        [DataMember(Name = "sn", EmitDefaultValue = false)]
        public string Sn { get; set; }

        /// <summary>
        /// 厂商ID
        /// </summary>
        /// <value>厂商ID</value>
        [DataMember(Name = "supplier_id", EmitDefaultValue = false)]
        public string SupplierId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayCommerceIotSdarttoolMessageSendModel {\n");
            sb.Append("  BiDa: ").Append(BiDa).Append("\n");
            sb.Append("  DeviceQueryType: ").Append(DeviceQueryType).Append("\n");
            sb.Append("  ImmediateMsg: ").Append(ImmediateMsg).Append("\n");
            sb.Append("  ItemId: ").Append(ItemId).Append("\n");
            sb.Append("  MsgContent: ").Append(MsgContent).Append("\n");
            sb.Append("  MsgContentType: ").Append(MsgContentType).Append("\n");
            sb.Append("  MsgExpire: ").Append(MsgExpire).Append("\n");
            sb.Append("  MsgPriority: ").Append(MsgPriority).Append("\n");
            sb.Append("  MsgType: ").Append(MsgType).Append("\n");
            sb.Append("  ServiceId: ").Append(ServiceId).Append("\n");
            sb.Append("  Sn: ").Append(Sn).Append("\n");
            sb.Append("  SupplierId: ").Append(SupplierId).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as AlipayCommerceIotSdarttoolMessageSendModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceIotSdarttoolMessageSendModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceIotSdarttoolMessageSendModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceIotSdarttoolMessageSendModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BiDa == input.BiDa ||
                    this.BiDa.Equals(input.BiDa)
                ) && 
                (
                    this.DeviceQueryType == input.DeviceQueryType ||
                    (this.DeviceQueryType != null &&
                    this.DeviceQueryType.Equals(input.DeviceQueryType))
                ) && 
                (
                    this.ImmediateMsg == input.ImmediateMsg ||
                    this.ImmediateMsg.Equals(input.ImmediateMsg)
                ) && 
                (
                    this.ItemId == input.ItemId ||
                    (this.ItemId != null &&
                    this.ItemId.Equals(input.ItemId))
                ) && 
                (
                    this.MsgContent == input.MsgContent ||
                    (this.MsgContent != null &&
                    this.MsgContent.Equals(input.MsgContent))
                ) && 
                (
                    this.MsgContentType == input.MsgContentType ||
                    (this.MsgContentType != null &&
                    this.MsgContentType.Equals(input.MsgContentType))
                ) && 
                (
                    this.MsgExpire == input.MsgExpire ||
                    this.MsgExpire.Equals(input.MsgExpire)
                ) && 
                (
                    this.MsgPriority == input.MsgPriority ||
                    this.MsgPriority.Equals(input.MsgPriority)
                ) && 
                (
                    this.MsgType == input.MsgType ||
                    (this.MsgType != null &&
                    this.MsgType.Equals(input.MsgType))
                ) && 
                (
                    this.ServiceId == input.ServiceId ||
                    (this.ServiceId != null &&
                    this.ServiceId.Equals(input.ServiceId))
                ) && 
                (
                    this.Sn == input.Sn ||
                    (this.Sn != null &&
                    this.Sn.Equals(input.Sn))
                ) && 
                (
                    this.SupplierId == input.SupplierId ||
                    (this.SupplierId != null &&
                    this.SupplierId.Equals(input.SupplierId))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                hashCode = (hashCode * 59) + this.BiDa.GetHashCode();
                if (this.DeviceQueryType != null)
                {
                    hashCode = (hashCode * 59) + this.DeviceQueryType.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.ImmediateMsg.GetHashCode();
                if (this.ItemId != null)
                {
                    hashCode = (hashCode * 59) + this.ItemId.GetHashCode();
                }
                if (this.MsgContent != null)
                {
                    hashCode = (hashCode * 59) + this.MsgContent.GetHashCode();
                }
                if (this.MsgContentType != null)
                {
                    hashCode = (hashCode * 59) + this.MsgContentType.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.MsgExpire.GetHashCode();
                hashCode = (hashCode * 59) + this.MsgPriority.GetHashCode();
                if (this.MsgType != null)
                {
                    hashCode = (hashCode * 59) + this.MsgType.GetHashCode();
                }
                if (this.ServiceId != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceId.GetHashCode();
                }
                if (this.Sn != null)
                {
                    hashCode = (hashCode * 59) + this.Sn.GetHashCode();
                }
                if (this.SupplierId != null)
                {
                    hashCode = (hashCode * 59) + this.SupplierId.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
