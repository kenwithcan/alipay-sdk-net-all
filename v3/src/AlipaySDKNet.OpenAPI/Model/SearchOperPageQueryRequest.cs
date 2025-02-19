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
    /// SearchOperPageQueryRequest
    /// </summary>
    [DataContract(Name = "SearchOperPageQueryRequest")]
    public partial class SearchOperPageQueryRequest : IEquatable<SearchOperPageQueryRequest>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SearchOperPageQueryRequest" /> class.
        /// </summary>
        /// <param name="accessType">申请类型 BASE：基础信息， BRAND_BOX：品牌直达，SERVICE_BOX服务直达.</param>
        /// <param name="appid">小程序ID.</param>
        /// <param name="pageNum">当前页.</param>
        /// <param name="pageSize">每页显示条数.</param>
        /// <param name="sceneCode">场景码.</param>
        /// <param name="specCode">服务类型 SP_MINI_APP 小程序 SP_PUBLIC_APP 生活号.</param>
        public SearchOperPageQueryRequest(string accessType = default(string), string appid = default(string), string pageNum = default(string), string pageSize = default(string), string sceneCode = default(string), string specCode = default(string))
        {
            this.AccessType = accessType;
            this.Appid = appid;
            this.PageNum = pageNum;
            this.PageSize = pageSize;
            this.SceneCode = sceneCode;
            this.SpecCode = specCode;
        }

        /// <summary>
        /// 申请类型 BASE：基础信息， BRAND_BOX：品牌直达，SERVICE_BOX服务直达
        /// </summary>
        /// <value>申请类型 BASE：基础信息， BRAND_BOX：品牌直达，SERVICE_BOX服务直达</value>
        [DataMember(Name = "access_type", EmitDefaultValue = false)]
        public string AccessType { get; set; }

        /// <summary>
        /// 小程序ID
        /// </summary>
        /// <value>小程序ID</value>
        [DataMember(Name = "appid", EmitDefaultValue = false)]
        public string Appid { get; set; }

        /// <summary>
        /// 当前页
        /// </summary>
        /// <value>当前页</value>
        [DataMember(Name = "page_num", EmitDefaultValue = false)]
        public string PageNum { get; set; }

        /// <summary>
        /// 每页显示条数
        /// </summary>
        /// <value>每页显示条数</value>
        [DataMember(Name = "page_size", EmitDefaultValue = false)]
        public string PageSize { get; set; }

        /// <summary>
        /// 场景码
        /// </summary>
        /// <value>场景码</value>
        [DataMember(Name = "scene_code", EmitDefaultValue = false)]
        public string SceneCode { get; set; }

        /// <summary>
        /// 服务类型 SP_MINI_APP 小程序 SP_PUBLIC_APP 生活号
        /// </summary>
        /// <value>服务类型 SP_MINI_APP 小程序 SP_PUBLIC_APP 生活号</value>
        [DataMember(Name = "spec_code", EmitDefaultValue = false)]
        public string SpecCode { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class SearchOperPageQueryRequest {\n");
            sb.Append("  AccessType: ").Append(AccessType).Append("\n");
            sb.Append("  Appid: ").Append(Appid).Append("\n");
            sb.Append("  PageNum: ").Append(PageNum).Append("\n");
            sb.Append("  PageSize: ").Append(PageSize).Append("\n");
            sb.Append("  SceneCode: ").Append(SceneCode).Append("\n");
            sb.Append("  SpecCode: ").Append(SpecCode).Append("\n");
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
            return this.Equals(input as SearchOperPageQueryRequest);
        }

        /// <summary>
        /// Returns true if SearchOperPageQueryRequest instances are equal
        /// </summary>
        /// <param name="input">Instance of SearchOperPageQueryRequest to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(SearchOperPageQueryRequest input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccessType == input.AccessType ||
                    (this.AccessType != null &&
                    this.AccessType.Equals(input.AccessType))
                ) && 
                (
                    this.Appid == input.Appid ||
                    (this.Appid != null &&
                    this.Appid.Equals(input.Appid))
                ) && 
                (
                    this.PageNum == input.PageNum ||
                    (this.PageNum != null &&
                    this.PageNum.Equals(input.PageNum))
                ) && 
                (
                    this.PageSize == input.PageSize ||
                    (this.PageSize != null &&
                    this.PageSize.Equals(input.PageSize))
                ) && 
                (
                    this.SceneCode == input.SceneCode ||
                    (this.SceneCode != null &&
                    this.SceneCode.Equals(input.SceneCode))
                ) && 
                (
                    this.SpecCode == input.SpecCode ||
                    (this.SpecCode != null &&
                    this.SpecCode.Equals(input.SpecCode))
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
                if (this.AccessType != null)
                {
                    hashCode = (hashCode * 59) + this.AccessType.GetHashCode();
                }
                if (this.Appid != null)
                {
                    hashCode = (hashCode * 59) + this.Appid.GetHashCode();
                }
                if (this.PageNum != null)
                {
                    hashCode = (hashCode * 59) + this.PageNum.GetHashCode();
                }
                if (this.PageSize != null)
                {
                    hashCode = (hashCode * 59) + this.PageSize.GetHashCode();
                }
                if (this.SceneCode != null)
                {
                    hashCode = (hashCode * 59) + this.SceneCode.GetHashCode();
                }
                if (this.SpecCode != null)
                {
                    hashCode = (hashCode * 59) + this.SpecCode.GetHashCode();
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
