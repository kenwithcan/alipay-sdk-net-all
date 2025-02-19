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
    /// DeliverAddress
    /// </summary>
    [DataContract(Name = "DeliverAddress")]
    public partial class DeliverAddress : IEquatable<DeliverAddress>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DeliverAddress" /> class.
        /// </summary>
        /// <param name="address">地址.</param>
        /// <param name="addressCode">区域编码.</param>
        /// <param name="defaultDeliverAddress">是否默认收货地址.</param>
        /// <param name="deliverArea">收货人所在区县.</param>
        /// <param name="deliverCity">收货人所在城市.</param>
        /// <param name="deliverFullname">收货人全名.</param>
        /// <param name="deliverMobile">收货地址的联系人移动电话.</param>
        /// <param name="deliverPhone">收货地址的联系人固定电话.</param>
        /// <param name="deliverProvince">收货人所在省份.</param>
        /// <param name="zip">邮政编码.</param>
        public DeliverAddress(string address = default(string), string addressCode = default(string), string defaultDeliverAddress = default(string), string deliverArea = default(string), string deliverCity = default(string), string deliverFullname = default(string), string deliverMobile = default(string), string deliverPhone = default(string), string deliverProvince = default(string), string zip = default(string))
        {
            this.Address = address;
            this.AddressCode = addressCode;
            this.DefaultDeliverAddress = defaultDeliverAddress;
            this.DeliverArea = deliverArea;
            this.DeliverCity = deliverCity;
            this.DeliverFullname = deliverFullname;
            this.DeliverMobile = deliverMobile;
            this.DeliverPhone = deliverPhone;
            this.DeliverProvince = deliverProvince;
            this.Zip = zip;
        }

        /// <summary>
        /// 地址
        /// </summary>
        /// <value>地址</value>
        [DataMember(Name = "address", EmitDefaultValue = false)]
        public string Address { get; set; }

        /// <summary>
        /// 区域编码
        /// </summary>
        /// <value>区域编码</value>
        [DataMember(Name = "address_code", EmitDefaultValue = false)]
        public string AddressCode { get; set; }

        /// <summary>
        /// 是否默认收货地址
        /// </summary>
        /// <value>是否默认收货地址</value>
        [DataMember(Name = "default_deliver_address", EmitDefaultValue = false)]
        public string DefaultDeliverAddress { get; set; }

        /// <summary>
        /// 收货人所在区县
        /// </summary>
        /// <value>收货人所在区县</value>
        [DataMember(Name = "deliver_area", EmitDefaultValue = false)]
        public string DeliverArea { get; set; }

        /// <summary>
        /// 收货人所在城市
        /// </summary>
        /// <value>收货人所在城市</value>
        [DataMember(Name = "deliver_city", EmitDefaultValue = false)]
        public string DeliverCity { get; set; }

        /// <summary>
        /// 收货人全名
        /// </summary>
        /// <value>收货人全名</value>
        [DataMember(Name = "deliver_fullname", EmitDefaultValue = false)]
        public string DeliverFullname { get; set; }

        /// <summary>
        /// 收货地址的联系人移动电话
        /// </summary>
        /// <value>收货地址的联系人移动电话</value>
        [DataMember(Name = "deliver_mobile", EmitDefaultValue = false)]
        public string DeliverMobile { get; set; }

        /// <summary>
        /// 收货地址的联系人固定电话
        /// </summary>
        /// <value>收货地址的联系人固定电话</value>
        [DataMember(Name = "deliver_phone", EmitDefaultValue = false)]
        public string DeliverPhone { get; set; }

        /// <summary>
        /// 收货人所在省份
        /// </summary>
        /// <value>收货人所在省份</value>
        [DataMember(Name = "deliver_province", EmitDefaultValue = false)]
        public string DeliverProvince { get; set; }

        /// <summary>
        /// 邮政编码
        /// </summary>
        /// <value>邮政编码</value>
        [DataMember(Name = "zip", EmitDefaultValue = false)]
        public string Zip { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class DeliverAddress {\n");
            sb.Append("  Address: ").Append(Address).Append("\n");
            sb.Append("  AddressCode: ").Append(AddressCode).Append("\n");
            sb.Append("  DefaultDeliverAddress: ").Append(DefaultDeliverAddress).Append("\n");
            sb.Append("  DeliverArea: ").Append(DeliverArea).Append("\n");
            sb.Append("  DeliverCity: ").Append(DeliverCity).Append("\n");
            sb.Append("  DeliverFullname: ").Append(DeliverFullname).Append("\n");
            sb.Append("  DeliverMobile: ").Append(DeliverMobile).Append("\n");
            sb.Append("  DeliverPhone: ").Append(DeliverPhone).Append("\n");
            sb.Append("  DeliverProvince: ").Append(DeliverProvince).Append("\n");
            sb.Append("  Zip: ").Append(Zip).Append("\n");
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
            return this.Equals(input as DeliverAddress);
        }

        /// <summary>
        /// Returns true if DeliverAddress instances are equal
        /// </summary>
        /// <param name="input">Instance of DeliverAddress to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(DeliverAddress input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Address == input.Address ||
                    (this.Address != null &&
                    this.Address.Equals(input.Address))
                ) && 
                (
                    this.AddressCode == input.AddressCode ||
                    (this.AddressCode != null &&
                    this.AddressCode.Equals(input.AddressCode))
                ) && 
                (
                    this.DefaultDeliverAddress == input.DefaultDeliverAddress ||
                    (this.DefaultDeliverAddress != null &&
                    this.DefaultDeliverAddress.Equals(input.DefaultDeliverAddress))
                ) && 
                (
                    this.DeliverArea == input.DeliverArea ||
                    (this.DeliverArea != null &&
                    this.DeliverArea.Equals(input.DeliverArea))
                ) && 
                (
                    this.DeliverCity == input.DeliverCity ||
                    (this.DeliverCity != null &&
                    this.DeliverCity.Equals(input.DeliverCity))
                ) && 
                (
                    this.DeliverFullname == input.DeliverFullname ||
                    (this.DeliverFullname != null &&
                    this.DeliverFullname.Equals(input.DeliverFullname))
                ) && 
                (
                    this.DeliverMobile == input.DeliverMobile ||
                    (this.DeliverMobile != null &&
                    this.DeliverMobile.Equals(input.DeliverMobile))
                ) && 
                (
                    this.DeliverPhone == input.DeliverPhone ||
                    (this.DeliverPhone != null &&
                    this.DeliverPhone.Equals(input.DeliverPhone))
                ) && 
                (
                    this.DeliverProvince == input.DeliverProvince ||
                    (this.DeliverProvince != null &&
                    this.DeliverProvince.Equals(input.DeliverProvince))
                ) && 
                (
                    this.Zip == input.Zip ||
                    (this.Zip != null &&
                    this.Zip.Equals(input.Zip))
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
                if (this.Address != null)
                {
                    hashCode = (hashCode * 59) + this.Address.GetHashCode();
                }
                if (this.AddressCode != null)
                {
                    hashCode = (hashCode * 59) + this.AddressCode.GetHashCode();
                }
                if (this.DefaultDeliverAddress != null)
                {
                    hashCode = (hashCode * 59) + this.DefaultDeliverAddress.GetHashCode();
                }
                if (this.DeliverArea != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverArea.GetHashCode();
                }
                if (this.DeliverCity != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverCity.GetHashCode();
                }
                if (this.DeliverFullname != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverFullname.GetHashCode();
                }
                if (this.DeliverMobile != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverMobile.GetHashCode();
                }
                if (this.DeliverPhone != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverPhone.GetHashCode();
                }
                if (this.DeliverProvince != null)
                {
                    hashCode = (hashCode * 59) + this.DeliverProvince.GetHashCode();
                }
                if (this.Zip != null)
                {
                    hashCode = (hashCode * 59) + this.Zip.GetHashCode();
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
