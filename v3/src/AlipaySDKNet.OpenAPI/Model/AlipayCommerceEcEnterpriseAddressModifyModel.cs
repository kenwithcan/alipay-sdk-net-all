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
    /// AlipayCommerceEcEnterpriseAddressModifyModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceEcEnterpriseAddressModifyModel")]
    public partial class AlipayCommerceEcEnterpriseAddressModifyModel : IEquatable<AlipayCommerceEcEnterpriseAddressModifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEcEnterpriseAddressModifyModel" /> class.
        /// </summary>
        /// <param name="accountId">通过企业码1.0接口签约的共同账户，和agreement_no搭配使用。.</param>
        /// <param name="address">详细地址最长50个字符.</param>
        /// <param name="addressId">地址id.</param>
        /// <param name="agreementNo">可通过签约消息获取。配合共同账户id使用，当填写企业共同账户id时，此字段必填。.</param>
        /// <param name="cityCode">市(国家统一行政规划编码).</param>
        /// <param name="cityName">城市名称.</param>
        /// <param name="community">小区/楼宇.</param>
        /// <param name="enterpriseId">通过企业码2.0签约接口签约，只填写企业id，无需填写共同账户id和授权签约协议号。.</param>
        /// <param name="latitude">纬度.</param>
        /// <param name="longitude">经度.</param>
        /// <param name="mark">备注.</param>
        /// <param name="poiId">高德地图poi.</param>
        /// <param name="status">状态(生效/失效).</param>
        public AlipayCommerceEcEnterpriseAddressModifyModel(string accountId = default(string), string address = default(string), string addressId = default(string), string agreementNo = default(string), string cityCode = default(string), string cityName = default(string), string community = default(string), string enterpriseId = default(string), string latitude = default(string), string longitude = default(string), string mark = default(string), string poiId = default(string), string status = default(string))
        {
            this.AccountId = accountId;
            this.Address = address;
            this.AddressId = addressId;
            this.AgreementNo = agreementNo;
            this.CityCode = cityCode;
            this.CityName = cityName;
            this.Community = community;
            this.EnterpriseId = enterpriseId;
            this.Latitude = latitude;
            this.Longitude = longitude;
            this.Mark = mark;
            this.PoiId = poiId;
            this.Status = status;
        }

        /// <summary>
        /// 通过企业码1.0接口签约的共同账户，和agreement_no搭配使用。
        /// </summary>
        /// <value>通过企业码1.0接口签约的共同账户，和agreement_no搭配使用。</value>
        [DataMember(Name = "account_id", EmitDefaultValue = false)]
        public string AccountId { get; set; }

        /// <summary>
        /// 详细地址最长50个字符
        /// </summary>
        /// <value>详细地址最长50个字符</value>
        [DataMember(Name = "address", EmitDefaultValue = false)]
        public string Address { get; set; }

        /// <summary>
        /// 地址id
        /// </summary>
        /// <value>地址id</value>
        [DataMember(Name = "address_id", EmitDefaultValue = false)]
        public string AddressId { get; set; }

        /// <summary>
        /// 可通过签约消息获取。配合共同账户id使用，当填写企业共同账户id时，此字段必填。
        /// </summary>
        /// <value>可通过签约消息获取。配合共同账户id使用，当填写企业共同账户id时，此字段必填。</value>
        [DataMember(Name = "agreement_no", EmitDefaultValue = false)]
        public string AgreementNo { get; set; }

        /// <summary>
        /// 市(国家统一行政规划编码)
        /// </summary>
        /// <value>市(国家统一行政规划编码)</value>
        [DataMember(Name = "city_code", EmitDefaultValue = false)]
        public string CityCode { get; set; }

        /// <summary>
        /// 城市名称
        /// </summary>
        /// <value>城市名称</value>
        [DataMember(Name = "city_name", EmitDefaultValue = false)]
        public string CityName { get; set; }

        /// <summary>
        /// 小区/楼宇
        /// </summary>
        /// <value>小区/楼宇</value>
        [DataMember(Name = "community", EmitDefaultValue = false)]
        public string Community { get; set; }

        /// <summary>
        /// 通过企业码2.0签约接口签约，只填写企业id，无需填写共同账户id和授权签约协议号。
        /// </summary>
        /// <value>通过企业码2.0签约接口签约，只填写企业id，无需填写共同账户id和授权签约协议号。</value>
        [DataMember(Name = "enterprise_id", EmitDefaultValue = false)]
        public string EnterpriseId { get; set; }

        /// <summary>
        /// 纬度
        /// </summary>
        /// <value>纬度</value>
        [DataMember(Name = "latitude", EmitDefaultValue = false)]
        public string Latitude { get; set; }

        /// <summary>
        /// 经度
        /// </summary>
        /// <value>经度</value>
        [DataMember(Name = "longitude", EmitDefaultValue = false)]
        public string Longitude { get; set; }

        /// <summary>
        /// 备注
        /// </summary>
        /// <value>备注</value>
        [DataMember(Name = "mark", EmitDefaultValue = false)]
        public string Mark { get; set; }

        /// <summary>
        /// 高德地图poi
        /// </summary>
        /// <value>高德地图poi</value>
        [DataMember(Name = "poi_id", EmitDefaultValue = false)]
        public string PoiId { get; set; }

        /// <summary>
        /// 状态(生效/失效)
        /// </summary>
        /// <value>状态(生效/失效)</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayCommerceEcEnterpriseAddressModifyModel {\n");
            sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            sb.Append("  Address: ").Append(Address).Append("\n");
            sb.Append("  AddressId: ").Append(AddressId).Append("\n");
            sb.Append("  AgreementNo: ").Append(AgreementNo).Append("\n");
            sb.Append("  CityCode: ").Append(CityCode).Append("\n");
            sb.Append("  CityName: ").Append(CityName).Append("\n");
            sb.Append("  Community: ").Append(Community).Append("\n");
            sb.Append("  EnterpriseId: ").Append(EnterpriseId).Append("\n");
            sb.Append("  Latitude: ").Append(Latitude).Append("\n");
            sb.Append("  Longitude: ").Append(Longitude).Append("\n");
            sb.Append("  Mark: ").Append(Mark).Append("\n");
            sb.Append("  PoiId: ").Append(PoiId).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
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
            return this.Equals(input as AlipayCommerceEcEnterpriseAddressModifyModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceEcEnterpriseAddressModifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceEcEnterpriseAddressModifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceEcEnterpriseAddressModifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccountId == input.AccountId ||
                    (this.AccountId != null &&
                    this.AccountId.Equals(input.AccountId))
                ) && 
                (
                    this.Address == input.Address ||
                    (this.Address != null &&
                    this.Address.Equals(input.Address))
                ) && 
                (
                    this.AddressId == input.AddressId ||
                    (this.AddressId != null &&
                    this.AddressId.Equals(input.AddressId))
                ) && 
                (
                    this.AgreementNo == input.AgreementNo ||
                    (this.AgreementNo != null &&
                    this.AgreementNo.Equals(input.AgreementNo))
                ) && 
                (
                    this.CityCode == input.CityCode ||
                    (this.CityCode != null &&
                    this.CityCode.Equals(input.CityCode))
                ) && 
                (
                    this.CityName == input.CityName ||
                    (this.CityName != null &&
                    this.CityName.Equals(input.CityName))
                ) && 
                (
                    this.Community == input.Community ||
                    (this.Community != null &&
                    this.Community.Equals(input.Community))
                ) && 
                (
                    this.EnterpriseId == input.EnterpriseId ||
                    (this.EnterpriseId != null &&
                    this.EnterpriseId.Equals(input.EnterpriseId))
                ) && 
                (
                    this.Latitude == input.Latitude ||
                    (this.Latitude != null &&
                    this.Latitude.Equals(input.Latitude))
                ) && 
                (
                    this.Longitude == input.Longitude ||
                    (this.Longitude != null &&
                    this.Longitude.Equals(input.Longitude))
                ) && 
                (
                    this.Mark == input.Mark ||
                    (this.Mark != null &&
                    this.Mark.Equals(input.Mark))
                ) && 
                (
                    this.PoiId == input.PoiId ||
                    (this.PoiId != null &&
                    this.PoiId.Equals(input.PoiId))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
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
                if (this.AccountId != null)
                {
                    hashCode = (hashCode * 59) + this.AccountId.GetHashCode();
                }
                if (this.Address != null)
                {
                    hashCode = (hashCode * 59) + this.Address.GetHashCode();
                }
                if (this.AddressId != null)
                {
                    hashCode = (hashCode * 59) + this.AddressId.GetHashCode();
                }
                if (this.AgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementNo.GetHashCode();
                }
                if (this.CityCode != null)
                {
                    hashCode = (hashCode * 59) + this.CityCode.GetHashCode();
                }
                if (this.CityName != null)
                {
                    hashCode = (hashCode * 59) + this.CityName.GetHashCode();
                }
                if (this.Community != null)
                {
                    hashCode = (hashCode * 59) + this.Community.GetHashCode();
                }
                if (this.EnterpriseId != null)
                {
                    hashCode = (hashCode * 59) + this.EnterpriseId.GetHashCode();
                }
                if (this.Latitude != null)
                {
                    hashCode = (hashCode * 59) + this.Latitude.GetHashCode();
                }
                if (this.Longitude != null)
                {
                    hashCode = (hashCode * 59) + this.Longitude.GetHashCode();
                }
                if (this.Mark != null)
                {
                    hashCode = (hashCode * 59) + this.Mark.GetHashCode();
                }
                if (this.PoiId != null)
                {
                    hashCode = (hashCode * 59) + this.PoiId.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
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
