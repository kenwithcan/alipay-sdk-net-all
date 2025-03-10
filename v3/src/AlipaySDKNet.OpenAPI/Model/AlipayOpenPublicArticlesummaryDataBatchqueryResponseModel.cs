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
    /// AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel")]
    public partial class AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel : IEquatable<AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel" /> class.
        /// </summary>
        /// <param name="dataList">文章分析数据列表.</param>
        public AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel(List<ArticleSummaryAnalysisData> dataList = default(List<ArticleSummaryAnalysisData>))
        {
            this.DataList = dataList;
        }

        /// <summary>
        /// 文章分析数据列表
        /// </summary>
        /// <value>文章分析数据列表</value>
        [DataMember(Name = "data_list", EmitDefaultValue = false)]
        public List<ArticleSummaryAnalysisData> DataList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel {\n");
            sb.Append("  DataList: ").Append(DataList).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicArticlesummaryDataBatchqueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.DataList == input.DataList ||
                    this.DataList != null &&
                    input.DataList != null &&
                    this.DataList.SequenceEqual(input.DataList)
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
                if (this.DataList != null)
                {
                    hashCode = (hashCode * 59) + this.DataList.GetHashCode();
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
