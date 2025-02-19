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
    /// UserMailInfoOrder
    /// </summary>
    [DataContract(Name = "UserMailInfoOrder")]
    public partial class UserMailInfoOrder : IEquatable<UserMailInfoOrder>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserMailInfoOrder" /> class.
        /// </summary>
        /// <param name="city">联系所在城市.</param>
        /// <param name="country">联系人国家.</param>
        /// <param name="countyDistrict">联系人所在县/区.</param>
        /// <param name="detailAddress">联系所在详细地址.</param>
        /// <param name="email">电子邮箱.</param>
        /// <param name="ipRoleId">商户ipRole(pid).</param>
        /// <param name="name">联系人名字.</param>
        /// <param name="province">联系人省份.</param>
        /// <param name="street">联系人所在街道.</param>
        /// <param name="telephone">联系人电话.</param>
        public UserMailInfoOrder(string city = default(string), string country = default(string), string countyDistrict = default(string), string detailAddress = default(string), string email = default(string), string ipRoleId = default(string), string name = default(string), string province = default(string), string street = default(string), string telephone = default(string))
        {
            this.City = city;
            this.Country = country;
            this.CountyDistrict = countyDistrict;
            this.DetailAddress = detailAddress;
            this.Email = email;
            this.IpRoleId = ipRoleId;
            this.Name = name;
            this.Province = province;
            this.Street = street;
            this.Telephone = telephone;
        }

        /// <summary>
        /// 联系所在城市
        /// </summary>
        /// <value>联系所在城市</value>
        [DataMember(Name = "city", EmitDefaultValue = false)]
        public string City { get; set; }

        /// <summary>
        /// 联系人国家
        /// </summary>
        /// <value>联系人国家</value>
        [DataMember(Name = "country", EmitDefaultValue = false)]
        public string Country { get; set; }

        /// <summary>
        /// 联系人所在县/区
        /// </summary>
        /// <value>联系人所在县/区</value>
        [DataMember(Name = "county_district", EmitDefaultValue = false)]
        public string CountyDistrict { get; set; }

        /// <summary>
        /// 联系所在详细地址
        /// </summary>
        /// <value>联系所在详细地址</value>
        [DataMember(Name = "detail_address", EmitDefaultValue = false)]
        public string DetailAddress { get; set; }

        /// <summary>
        /// 电子邮箱
        /// </summary>
        /// <value>电子邮箱</value>
        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        /// <summary>
        /// 商户ipRole(pid)
        /// </summary>
        /// <value>商户ipRole(pid)</value>
        [DataMember(Name = "ip_role_id", EmitDefaultValue = false)]
        public string IpRoleId { get; set; }

        /// <summary>
        /// 联系人名字
        /// </summary>
        /// <value>联系人名字</value>
        [DataMember(Name = "name", EmitDefaultValue = false)]
        public string Name { get; set; }

        /// <summary>
        /// 联系人省份
        /// </summary>
        /// <value>联系人省份</value>
        [DataMember(Name = "province", EmitDefaultValue = false)]
        public string Province { get; set; }

        /// <summary>
        /// 联系人所在街道
        /// </summary>
        /// <value>联系人所在街道</value>
        [DataMember(Name = "street", EmitDefaultValue = false)]
        public string Street { get; set; }

        /// <summary>
        /// 联系人电话
        /// </summary>
        /// <value>联系人电话</value>
        [DataMember(Name = "telephone", EmitDefaultValue = false)]
        public string Telephone { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class UserMailInfoOrder {\n");
            sb.Append("  City: ").Append(City).Append("\n");
            sb.Append("  Country: ").Append(Country).Append("\n");
            sb.Append("  CountyDistrict: ").Append(CountyDistrict).Append("\n");
            sb.Append("  DetailAddress: ").Append(DetailAddress).Append("\n");
            sb.Append("  Email: ").Append(Email).Append("\n");
            sb.Append("  IpRoleId: ").Append(IpRoleId).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  Province: ").Append(Province).Append("\n");
            sb.Append("  Street: ").Append(Street).Append("\n");
            sb.Append("  Telephone: ").Append(Telephone).Append("\n");
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
            return this.Equals(input as UserMailInfoOrder);
        }

        /// <summary>
        /// Returns true if UserMailInfoOrder instances are equal
        /// </summary>
        /// <param name="input">Instance of UserMailInfoOrder to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(UserMailInfoOrder input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.City == input.City ||
                    (this.City != null &&
                    this.City.Equals(input.City))
                ) && 
                (
                    this.Country == input.Country ||
                    (this.Country != null &&
                    this.Country.Equals(input.Country))
                ) && 
                (
                    this.CountyDistrict == input.CountyDistrict ||
                    (this.CountyDistrict != null &&
                    this.CountyDistrict.Equals(input.CountyDistrict))
                ) && 
                (
                    this.DetailAddress == input.DetailAddress ||
                    (this.DetailAddress != null &&
                    this.DetailAddress.Equals(input.DetailAddress))
                ) && 
                (
                    this.Email == input.Email ||
                    (this.Email != null &&
                    this.Email.Equals(input.Email))
                ) && 
                (
                    this.IpRoleId == input.IpRoleId ||
                    (this.IpRoleId != null &&
                    this.IpRoleId.Equals(input.IpRoleId))
                ) && 
                (
                    this.Name == input.Name ||
                    (this.Name != null &&
                    this.Name.Equals(input.Name))
                ) && 
                (
                    this.Province == input.Province ||
                    (this.Province != null &&
                    this.Province.Equals(input.Province))
                ) && 
                (
                    this.Street == input.Street ||
                    (this.Street != null &&
                    this.Street.Equals(input.Street))
                ) && 
                (
                    this.Telephone == input.Telephone ||
                    (this.Telephone != null &&
                    this.Telephone.Equals(input.Telephone))
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
                if (this.City != null)
                {
                    hashCode = (hashCode * 59) + this.City.GetHashCode();
                }
                if (this.Country != null)
                {
                    hashCode = (hashCode * 59) + this.Country.GetHashCode();
                }
                if (this.CountyDistrict != null)
                {
                    hashCode = (hashCode * 59) + this.CountyDistrict.GetHashCode();
                }
                if (this.DetailAddress != null)
                {
                    hashCode = (hashCode * 59) + this.DetailAddress.GetHashCode();
                }
                if (this.Email != null)
                {
                    hashCode = (hashCode * 59) + this.Email.GetHashCode();
                }
                if (this.IpRoleId != null)
                {
                    hashCode = (hashCode * 59) + this.IpRoleId.GetHashCode();
                }
                if (this.Name != null)
                {
                    hashCode = (hashCode * 59) + this.Name.GetHashCode();
                }
                if (this.Province != null)
                {
                    hashCode = (hashCode * 59) + this.Province.GetHashCode();
                }
                if (this.Street != null)
                {
                    hashCode = (hashCode * 59) + this.Street.GetHashCode();
                }
                if (this.Telephone != null)
                {
                    hashCode = (hashCode * 59) + this.Telephone.GetHashCode();
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
