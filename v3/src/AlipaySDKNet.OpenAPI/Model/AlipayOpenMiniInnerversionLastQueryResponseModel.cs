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
    /// AlipayOpenMiniInnerversionLastQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniInnerversionLastQueryResponseModel")]
    public partial class AlipayOpenMiniInnerversionLastQueryResponseModel : IEquatable<AlipayOpenMiniInnerversionLastQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerversionLastQueryResponseModel" /> class.
        /// </summary>
        /// <param name="appDesc">小程序应用描述.</param>
        /// <param name="appName">小程序的名称.</param>
        /// <param name="appVersion">版本号.</param>
        /// <param name="bundleId">端信息.</param>
        /// <param name="categoryIds">小程序所属类目.</param>
        /// <param name="englishName">小程序英文名称.</param>
        /// <param name="logoUrl">小程序应用logo图标.</param>
        /// <param name="miniAppId">小程序ID.</param>
        /// <param name="servicePhone">小程序客服电话.</param>
        /// <param name="slogan">小程序应用简介，一句话描述小程序功能.</param>
        /// <param name="status">版本状态.</param>
        /// <param name="subApplicationType">小程序子类型，自研、模板类型.</param>
        public AlipayOpenMiniInnerversionLastQueryResponseModel(string appDesc = default(string), string appName = default(string), string appVersion = default(string), string bundleId = default(string), string categoryIds = default(string), string englishName = default(string), string logoUrl = default(string), string miniAppId = default(string), string servicePhone = default(string), string slogan = default(string), string status = default(string), string subApplicationType = default(string))
        {
            this.AppDesc = appDesc;
            this.AppName = appName;
            this.AppVersion = appVersion;
            this.BundleId = bundleId;
            this.CategoryIds = categoryIds;
            this.EnglishName = englishName;
            this.LogoUrl = logoUrl;
            this.MiniAppId = miniAppId;
            this.ServicePhone = servicePhone;
            this.Slogan = slogan;
            this.Status = status;
            this.SubApplicationType = subApplicationType;
        }

        /// <summary>
        /// 小程序应用描述
        /// </summary>
        /// <value>小程序应用描述</value>
        [DataMember(Name = "app_desc", EmitDefaultValue = false)]
        public string AppDesc { get; set; }

        /// <summary>
        /// 小程序的名称
        /// </summary>
        /// <value>小程序的名称</value>
        [DataMember(Name = "app_name", EmitDefaultValue = false)]
        public string AppName { get; set; }

        /// <summary>
        /// 版本号
        /// </summary>
        /// <value>版本号</value>
        [DataMember(Name = "app_version", EmitDefaultValue = false)]
        public string AppVersion { get; set; }

        /// <summary>
        /// 端信息
        /// </summary>
        /// <value>端信息</value>
        [DataMember(Name = "bundle_id", EmitDefaultValue = false)]
        public string BundleId { get; set; }

        /// <summary>
        /// 小程序所属类目
        /// </summary>
        /// <value>小程序所属类目</value>
        [DataMember(Name = "category_ids", EmitDefaultValue = false)]
        public string CategoryIds { get; set; }

        /// <summary>
        /// 小程序英文名称
        /// </summary>
        /// <value>小程序英文名称</value>
        [DataMember(Name = "english_name", EmitDefaultValue = false)]
        public string EnglishName { get; set; }

        /// <summary>
        /// 小程序应用logo图标
        /// </summary>
        /// <value>小程序应用logo图标</value>
        [DataMember(Name = "logo_url", EmitDefaultValue = false)]
        public string LogoUrl { get; set; }

        /// <summary>
        /// 小程序ID
        /// </summary>
        /// <value>小程序ID</value>
        [DataMember(Name = "mini_app_id", EmitDefaultValue = false)]
        public string MiniAppId { get; set; }

        /// <summary>
        /// 小程序客服电话
        /// </summary>
        /// <value>小程序客服电话</value>
        [DataMember(Name = "service_phone", EmitDefaultValue = false)]
        public string ServicePhone { get; set; }

        /// <summary>
        /// 小程序应用简介，一句话描述小程序功能
        /// </summary>
        /// <value>小程序应用简介，一句话描述小程序功能</value>
        [DataMember(Name = "slogan", EmitDefaultValue = false)]
        public string Slogan { get; set; }

        /// <summary>
        /// 版本状态
        /// </summary>
        /// <value>版本状态</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// 小程序子类型，自研、模板类型
        /// </summary>
        /// <value>小程序子类型，自研、模板类型</value>
        [DataMember(Name = "sub_application_type", EmitDefaultValue = false)]
        public string SubApplicationType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenMiniInnerversionLastQueryResponseModel {\n");
            sb.Append("  AppDesc: ").Append(AppDesc).Append("\n");
            sb.Append("  AppName: ").Append(AppName).Append("\n");
            sb.Append("  AppVersion: ").Append(AppVersion).Append("\n");
            sb.Append("  BundleId: ").Append(BundleId).Append("\n");
            sb.Append("  CategoryIds: ").Append(CategoryIds).Append("\n");
            sb.Append("  EnglishName: ").Append(EnglishName).Append("\n");
            sb.Append("  LogoUrl: ").Append(LogoUrl).Append("\n");
            sb.Append("  MiniAppId: ").Append(MiniAppId).Append("\n");
            sb.Append("  ServicePhone: ").Append(ServicePhone).Append("\n");
            sb.Append("  Slogan: ").Append(Slogan).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  SubApplicationType: ").Append(SubApplicationType).Append("\n");
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
            return this.Equals(input as AlipayOpenMiniInnerversionLastQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniInnerversionLastQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniInnerversionLastQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniInnerversionLastQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AppDesc == input.AppDesc ||
                    (this.AppDesc != null &&
                    this.AppDesc.Equals(input.AppDesc))
                ) && 
                (
                    this.AppName == input.AppName ||
                    (this.AppName != null &&
                    this.AppName.Equals(input.AppName))
                ) && 
                (
                    this.AppVersion == input.AppVersion ||
                    (this.AppVersion != null &&
                    this.AppVersion.Equals(input.AppVersion))
                ) && 
                (
                    this.BundleId == input.BundleId ||
                    (this.BundleId != null &&
                    this.BundleId.Equals(input.BundleId))
                ) && 
                (
                    this.CategoryIds == input.CategoryIds ||
                    (this.CategoryIds != null &&
                    this.CategoryIds.Equals(input.CategoryIds))
                ) && 
                (
                    this.EnglishName == input.EnglishName ||
                    (this.EnglishName != null &&
                    this.EnglishName.Equals(input.EnglishName))
                ) && 
                (
                    this.LogoUrl == input.LogoUrl ||
                    (this.LogoUrl != null &&
                    this.LogoUrl.Equals(input.LogoUrl))
                ) && 
                (
                    this.MiniAppId == input.MiniAppId ||
                    (this.MiniAppId != null &&
                    this.MiniAppId.Equals(input.MiniAppId))
                ) && 
                (
                    this.ServicePhone == input.ServicePhone ||
                    (this.ServicePhone != null &&
                    this.ServicePhone.Equals(input.ServicePhone))
                ) && 
                (
                    this.Slogan == input.Slogan ||
                    (this.Slogan != null &&
                    this.Slogan.Equals(input.Slogan))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
                ) && 
                (
                    this.SubApplicationType == input.SubApplicationType ||
                    (this.SubApplicationType != null &&
                    this.SubApplicationType.Equals(input.SubApplicationType))
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
                if (this.AppDesc != null)
                {
                    hashCode = (hashCode * 59) + this.AppDesc.GetHashCode();
                }
                if (this.AppName != null)
                {
                    hashCode = (hashCode * 59) + this.AppName.GetHashCode();
                }
                if (this.AppVersion != null)
                {
                    hashCode = (hashCode * 59) + this.AppVersion.GetHashCode();
                }
                if (this.BundleId != null)
                {
                    hashCode = (hashCode * 59) + this.BundleId.GetHashCode();
                }
                if (this.CategoryIds != null)
                {
                    hashCode = (hashCode * 59) + this.CategoryIds.GetHashCode();
                }
                if (this.EnglishName != null)
                {
                    hashCode = (hashCode * 59) + this.EnglishName.GetHashCode();
                }
                if (this.LogoUrl != null)
                {
                    hashCode = (hashCode * 59) + this.LogoUrl.GetHashCode();
                }
                if (this.MiniAppId != null)
                {
                    hashCode = (hashCode * 59) + this.MiniAppId.GetHashCode();
                }
                if (this.ServicePhone != null)
                {
                    hashCode = (hashCode * 59) + this.ServicePhone.GetHashCode();
                }
                if (this.Slogan != null)
                {
                    hashCode = (hashCode * 59) + this.Slogan.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
                }
                if (this.SubApplicationType != null)
                {
                    hashCode = (hashCode * 59) + this.SubApplicationType.GetHashCode();
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
