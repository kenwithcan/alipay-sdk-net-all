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
    /// AlipayMerchantIotDeviceVerifyModel
    /// </summary>
    [DataContract(Name = "AlipayMerchantIotDeviceVerifyModel")]
    public partial class AlipayMerchantIotDeviceVerifyModel : IEquatable<AlipayMerchantIotDeviceVerifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMerchantIotDeviceVerifyModel" /> class.
        /// </summary>
        /// <param name="bizTid">设备 ID ，device_id_type 为 ID 时填写。.</param>
        /// <param name="deviceIdType">可选方式 [ID,SN]。ID-使用biztid作为设备唯一识别标识；SN-使用supplier_id、device_sn联合作为设备唯一识别标识。由于不同机型的supplier_id不同，推荐使用 ID 。.</param>
        /// <param name="deviceSn">设备序列号 ，device_id_type 为 SN 时填写。需配合supplier_id使用。.</param>
        /// <param name="merchantType">商户类型，直连商户填写direct，间连商户填写indirect.</param>
        /// <param name="pid">直连场景填写商户收单pid，间连场景不填.</param>
        /// <param name="smid">直连场景不填，间连场景填写商户收单smid.</param>
        /// <param name="supplierId">设备供应商ID ，device_id_type 为 SN 时填写。需注意不同机型的供应商ID可能不同。.</param>
        public AlipayMerchantIotDeviceVerifyModel(string bizTid = default(string), string deviceIdType = default(string), string deviceSn = default(string), string merchantType = default(string), string pid = default(string), string smid = default(string), string supplierId = default(string))
        {
            this.BizTid = bizTid;
            this.DeviceIdType = deviceIdType;
            this.DeviceSn = deviceSn;
            this.MerchantType = merchantType;
            this.Pid = pid;
            this.Smid = smid;
            this.SupplierId = supplierId;
        }

        /// <summary>
        /// 设备 ID ，device_id_type 为 ID 时填写。
        /// </summary>
        /// <value>设备 ID ，device_id_type 为 ID 时填写。</value>
        [DataMember(Name = "biz_tid", EmitDefaultValue = false)]
        public string BizTid { get; set; }

        /// <summary>
        /// 可选方式 [ID,SN]。ID-使用biztid作为设备唯一识别标识；SN-使用supplier_id、device_sn联合作为设备唯一识别标识。由于不同机型的supplier_id不同，推荐使用 ID 。
        /// </summary>
        /// <value>可选方式 [ID,SN]。ID-使用biztid作为设备唯一识别标识；SN-使用supplier_id、device_sn联合作为设备唯一识别标识。由于不同机型的supplier_id不同，推荐使用 ID 。</value>
        [DataMember(Name = "device_id_type", EmitDefaultValue = false)]
        public string DeviceIdType { get; set; }

        /// <summary>
        /// 设备序列号 ，device_id_type 为 SN 时填写。需配合supplier_id使用。
        /// </summary>
        /// <value>设备序列号 ，device_id_type 为 SN 时填写。需配合supplier_id使用。</value>
        [DataMember(Name = "device_sn", EmitDefaultValue = false)]
        public string DeviceSn { get; set; }

        /// <summary>
        /// 商户类型，直连商户填写direct，间连商户填写indirect
        /// </summary>
        /// <value>商户类型，直连商户填写direct，间连商户填写indirect</value>
        [DataMember(Name = "merchant_type", EmitDefaultValue = false)]
        public string MerchantType { get; set; }

        /// <summary>
        /// 直连场景填写商户收单pid，间连场景不填
        /// </summary>
        /// <value>直连场景填写商户收单pid，间连场景不填</value>
        [DataMember(Name = "pid", EmitDefaultValue = false)]
        public string Pid { get; set; }

        /// <summary>
        /// 直连场景不填，间连场景填写商户收单smid
        /// </summary>
        /// <value>直连场景不填，间连场景填写商户收单smid</value>
        [DataMember(Name = "smid", EmitDefaultValue = false)]
        public string Smid { get; set; }

        /// <summary>
        /// 设备供应商ID ，device_id_type 为 SN 时填写。需注意不同机型的供应商ID可能不同。
        /// </summary>
        /// <value>设备供应商ID ，device_id_type 为 SN 时填写。需注意不同机型的供应商ID可能不同。</value>
        [DataMember(Name = "supplier_id", EmitDefaultValue = false)]
        public string SupplierId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMerchantIotDeviceVerifyModel {\n");
            sb.Append("  BizTid: ").Append(BizTid).Append("\n");
            sb.Append("  DeviceIdType: ").Append(DeviceIdType).Append("\n");
            sb.Append("  DeviceSn: ").Append(DeviceSn).Append("\n");
            sb.Append("  MerchantType: ").Append(MerchantType).Append("\n");
            sb.Append("  Pid: ").Append(Pid).Append("\n");
            sb.Append("  Smid: ").Append(Smid).Append("\n");
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
            return this.Equals(input as AlipayMerchantIotDeviceVerifyModel);
        }

        /// <summary>
        /// Returns true if AlipayMerchantIotDeviceVerifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMerchantIotDeviceVerifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMerchantIotDeviceVerifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BizTid == input.BizTid ||
                    (this.BizTid != null &&
                    this.BizTid.Equals(input.BizTid))
                ) && 
                (
                    this.DeviceIdType == input.DeviceIdType ||
                    (this.DeviceIdType != null &&
                    this.DeviceIdType.Equals(input.DeviceIdType))
                ) && 
                (
                    this.DeviceSn == input.DeviceSn ||
                    (this.DeviceSn != null &&
                    this.DeviceSn.Equals(input.DeviceSn))
                ) && 
                (
                    this.MerchantType == input.MerchantType ||
                    (this.MerchantType != null &&
                    this.MerchantType.Equals(input.MerchantType))
                ) && 
                (
                    this.Pid == input.Pid ||
                    (this.Pid != null &&
                    this.Pid.Equals(input.Pid))
                ) && 
                (
                    this.Smid == input.Smid ||
                    (this.Smid != null &&
                    this.Smid.Equals(input.Smid))
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
                if (this.BizTid != null)
                {
                    hashCode = (hashCode * 59) + this.BizTid.GetHashCode();
                }
                if (this.DeviceIdType != null)
                {
                    hashCode = (hashCode * 59) + this.DeviceIdType.GetHashCode();
                }
                if (this.DeviceSn != null)
                {
                    hashCode = (hashCode * 59) + this.DeviceSn.GetHashCode();
                }
                if (this.MerchantType != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantType.GetHashCode();
                }
                if (this.Pid != null)
                {
                    hashCode = (hashCode * 59) + this.Pid.GetHashCode();
                }
                if (this.Smid != null)
                {
                    hashCode = (hashCode * 59) + this.Smid.GetHashCode();
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
