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
    /// AlipayOpenMiniInnerversionAuditSubmitModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniInnerversionAuditSubmitModel")]
    public partial class AlipayOpenMiniInnerversionAuditSubmitModel : IEquatable<AlipayOpenMiniInnerversionAuditSubmitModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerversionAuditSubmitModel" /> class.
        /// </summary>
        /// <param name="appCategoryIds">小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考&lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt;，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。.</param>
        /// <param name="appDesc">小程序应用描述，20-200个字，如果不填默认采用当前小程序的应用描述.</param>
        /// <param name="appEnglishName">小程序应用英文名称，如果不填默认采用当前小程序应用英文名称，3～30个字符。插件不填.</param>
        /// <param name="appLogo">小程序logo图标，图片格式必须为：png、jpeg、jpg，比例必须为1:1，建议上传像素为180*180，不超过256kb， 如果不填默认采用当前小程序应用logo图标.</param>
        /// <param name="appName">小程序应用名称，如果不填默认采用当前小程序应用名称，名称3-40个字符，一个中文算两个字符.</param>
        /// <param name="appOrigin">来源类型，新接入方需要向支付宝申请专用来源，否则不予接入，申请方式请参见接入手册。.</param>
        /// <param name="appSlogan">小程序应用简介，一句话描述小程序功能，如果不填默认采用当前小程序应用简介，10~32个字符.</param>
        /// <param name="appVersion">需要提交审核的小程序版本号，格式为: x.y.z，其中x、y、z均为整型数字，一个应用最多只能有一个审核中、审核通过或者审核驳回的版本。.</param>
        /// <param name="bundleId">端ID，多端场景下区分不同端.</param>
        /// <param name="licenseInfo">licenseInfo.</param>
        /// <param name="memo">小程序备注.</param>
        /// <param name="miniAppId">小程序ID，特殊场景专用，普通业务方无需关注该参数。.</param>
        /// <param name="miniCategoryIds">新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/mini/03l8c6&#39;&gt;alipay.open.mini.category.query&lt;/a&gt;（小程序类目树查询接口）查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃.</param>
        /// <param name="openId">小程序所属PID.</param>
        /// <param name="outDoorPic">门头照图片地址，部分小程序类目需要提交，参照 &lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt; 中是否需要营业执照信息，如果不填默认采用当前小程序门头照图片.</param>
        /// <param name="pid">小程序所属PID.</param>
        /// <param name="screenShotList">小程序应用截图列表，逗号分割，需要2-5张图片，单张图片不能超过4MB，图片格式只支持jpg，png；通过模板实例化小程序不需要传递此参数。.</param>
        /// <param name="serviceEmail">小程序客服邮箱，如果不填默认采用当前小程序的应用客服邮箱，和客服电话至少填写一个.</param>
        /// <param name="servicePhone">小程序客服电话，如果不填默认采用当前小程序的应用客服电话，和客服邮箱至少填写一个。插件不填.</param>
        /// <param name="specialLicensePicList">特殊资质图片地址列表，逗号分隔；部分类目需要特殊资质，如果需要特殊资质，最少一张，最多三张。模板和插件不需要特殊资质.</param>
        /// <param name="versionDesc">小程序版本变更描述，30-500个字符，区分于app_desc.</param>
        public AlipayOpenMiniInnerversionAuditSubmitModel(string appCategoryIds = default(string), string appDesc = default(string), string appEnglishName = default(string), string appLogo = default(string), string appName = default(string), string appOrigin = default(string), string appSlogan = default(string), string appVersion = default(string), string bundleId = default(string), AuditLicenseInfo licenseInfo = default(AuditLicenseInfo), string memo = default(string), string miniAppId = default(string), string miniCategoryIds = default(string), string openId = default(string), string outDoorPic = default(string), string pid = default(string), List<string> screenShotList = default(List<string>), string serviceEmail = default(string), string servicePhone = default(string), string specialLicensePicList = default(string), string versionDesc = default(string))
        {
            this.AppCategoryIds = appCategoryIds;
            this.AppDesc = appDesc;
            this.AppEnglishName = appEnglishName;
            this.AppLogo = appLogo;
            this.AppName = appName;
            this.AppOrigin = appOrigin;
            this.AppSlogan = appSlogan;
            this.AppVersion = appVersion;
            this.BundleId = bundleId;
            this.LicenseInfo = licenseInfo;
            this.Memo = memo;
            this.MiniAppId = miniAppId;
            this.MiniCategoryIds = miniCategoryIds;
            this.OpenId = openId;
            this.OutDoorPic = outDoorPic;
            this.Pid = pid;
            this.ScreenShotList = screenShotList;
            this.ServiceEmail = serviceEmail;
            this.ServicePhone = servicePhone;
            this.SpecialLicensePicList = specialLicensePicList;
            this.VersionDesc = versionDesc;
        }

        /// <summary>
        /// 小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考&lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt;，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。
        /// </summary>
        /// <value>小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考&lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt;，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。</value>
        [DataMember(Name = "app_category_ids", EmitDefaultValue = false)]
        public string AppCategoryIds { get; set; }

        /// <summary>
        /// 小程序应用描述，20-200个字，如果不填默认采用当前小程序的应用描述
        /// </summary>
        /// <value>小程序应用描述，20-200个字，如果不填默认采用当前小程序的应用描述</value>
        [DataMember(Name = "app_desc", EmitDefaultValue = false)]
        public string AppDesc { get; set; }

        /// <summary>
        /// 小程序应用英文名称，如果不填默认采用当前小程序应用英文名称，3～30个字符。插件不填
        /// </summary>
        /// <value>小程序应用英文名称，如果不填默认采用当前小程序应用英文名称，3～30个字符。插件不填</value>
        [DataMember(Name = "app_english_name", EmitDefaultValue = false)]
        public string AppEnglishName { get; set; }

        /// <summary>
        /// 小程序logo图标，图片格式必须为：png、jpeg、jpg，比例必须为1:1，建议上传像素为180*180，不超过256kb， 如果不填默认采用当前小程序应用logo图标
        /// </summary>
        /// <value>小程序logo图标，图片格式必须为：png、jpeg、jpg，比例必须为1:1，建议上传像素为180*180，不超过256kb， 如果不填默认采用当前小程序应用logo图标</value>
        [DataMember(Name = "app_logo", EmitDefaultValue = false)]
        public string AppLogo { get; set; }

        /// <summary>
        /// 小程序应用名称，如果不填默认采用当前小程序应用名称，名称3-40个字符，一个中文算两个字符
        /// </summary>
        /// <value>小程序应用名称，如果不填默认采用当前小程序应用名称，名称3-40个字符，一个中文算两个字符</value>
        [DataMember(Name = "app_name", EmitDefaultValue = false)]
        public string AppName { get; set; }

        /// <summary>
        /// 来源类型，新接入方需要向支付宝申请专用来源，否则不予接入，申请方式请参见接入手册。
        /// </summary>
        /// <value>来源类型，新接入方需要向支付宝申请专用来源，否则不予接入，申请方式请参见接入手册。</value>
        [DataMember(Name = "app_origin", EmitDefaultValue = false)]
        public string AppOrigin { get; set; }

        /// <summary>
        /// 小程序应用简介，一句话描述小程序功能，如果不填默认采用当前小程序应用简介，10~32个字符
        /// </summary>
        /// <value>小程序应用简介，一句话描述小程序功能，如果不填默认采用当前小程序应用简介，10~32个字符</value>
        [DataMember(Name = "app_slogan", EmitDefaultValue = false)]
        public string AppSlogan { get; set; }

        /// <summary>
        /// 需要提交审核的小程序版本号，格式为: x.y.z，其中x、y、z均为整型数字，一个应用最多只能有一个审核中、审核通过或者审核驳回的版本。
        /// </summary>
        /// <value>需要提交审核的小程序版本号，格式为: x.y.z，其中x、y、z均为整型数字，一个应用最多只能有一个审核中、审核通过或者审核驳回的版本。</value>
        [DataMember(Name = "app_version", EmitDefaultValue = false)]
        public string AppVersion { get; set; }

        /// <summary>
        /// 端ID，多端场景下区分不同端
        /// </summary>
        /// <value>端ID，多端场景下区分不同端</value>
        [DataMember(Name = "bundle_id", EmitDefaultValue = false)]
        public string BundleId { get; set; }

        /// <summary>
        /// Gets or Sets LicenseInfo
        /// </summary>
        [DataMember(Name = "license_info", EmitDefaultValue = false)]
        public AuditLicenseInfo LicenseInfo { get; set; }

        /// <summary>
        /// 小程序备注
        /// </summary>
        /// <value>小程序备注</value>
        [DataMember(Name = "memo", EmitDefaultValue = false)]
        public string Memo { get; set; }

        /// <summary>
        /// 小程序ID，特殊场景专用，普通业务方无需关注该参数。
        /// </summary>
        /// <value>小程序ID，特殊场景专用，普通业务方无需关注该参数。</value>
        [DataMember(Name = "mini_app_id", EmitDefaultValue = false)]
        public string MiniAppId { get; set; }

        /// <summary>
        /// 新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/mini/03l8c6&#39;&gt;alipay.open.mini.category.query&lt;/a&gt;（小程序类目树查询接口）查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃
        /// </summary>
        /// <value>新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/mini/03l8c6&#39;&gt;alipay.open.mini.category.query&lt;/a&gt;（小程序类目树查询接口）查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃</value>
        [DataMember(Name = "mini_category_ids", EmitDefaultValue = false)]
        public string MiniCategoryIds { get; set; }

        /// <summary>
        /// 小程序所属PID
        /// </summary>
        /// <value>小程序所属PID</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 门头照图片地址，部分小程序类目需要提交，参照 &lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt; 中是否需要营业执照信息，如果不填默认采用当前小程序门头照图片
        /// </summary>
        /// <value>门头照图片地址，部分小程序类目需要提交，参照 &lt;a href&#x3D;‘https://opendocs.alipay.com/b/03al2m’&gt;开放服务类目&lt;/a&gt; 中是否需要营业执照信息，如果不填默认采用当前小程序门头照图片</value>
        [DataMember(Name = "out_door_pic", EmitDefaultValue = false)]
        public string OutDoorPic { get; set; }

        /// <summary>
        /// 小程序所属PID
        /// </summary>
        /// <value>小程序所属PID</value>
        [DataMember(Name = "pid", EmitDefaultValue = false)]
        public string Pid { get; set; }

        /// <summary>
        /// 小程序应用截图列表，逗号分割，需要2-5张图片，单张图片不能超过4MB，图片格式只支持jpg，png；通过模板实例化小程序不需要传递此参数。
        /// </summary>
        /// <value>小程序应用截图列表，逗号分割，需要2-5张图片，单张图片不能超过4MB，图片格式只支持jpg，png；通过模板实例化小程序不需要传递此参数。</value>
        [DataMember(Name = "screen_shot_list", EmitDefaultValue = false)]
        public List<string> ScreenShotList { get; set; }

        /// <summary>
        /// 小程序客服邮箱，如果不填默认采用当前小程序的应用客服邮箱，和客服电话至少填写一个
        /// </summary>
        /// <value>小程序客服邮箱，如果不填默认采用当前小程序的应用客服邮箱，和客服电话至少填写一个</value>
        [DataMember(Name = "service_email", EmitDefaultValue = false)]
        public string ServiceEmail { get; set; }

        /// <summary>
        /// 小程序客服电话，如果不填默认采用当前小程序的应用客服电话，和客服邮箱至少填写一个。插件不填
        /// </summary>
        /// <value>小程序客服电话，如果不填默认采用当前小程序的应用客服电话，和客服邮箱至少填写一个。插件不填</value>
        [DataMember(Name = "service_phone", EmitDefaultValue = false)]
        public string ServicePhone { get; set; }

        /// <summary>
        /// 特殊资质图片地址列表，逗号分隔；部分类目需要特殊资质，如果需要特殊资质，最少一张，最多三张。模板和插件不需要特殊资质
        /// </summary>
        /// <value>特殊资质图片地址列表，逗号分隔；部分类目需要特殊资质，如果需要特殊资质，最少一张，最多三张。模板和插件不需要特殊资质</value>
        [DataMember(Name = "special_license_pic_list", EmitDefaultValue = false)]
        public string SpecialLicensePicList { get; set; }

        /// <summary>
        /// 小程序版本变更描述，30-500个字符，区分于app_desc
        /// </summary>
        /// <value>小程序版本变更描述，30-500个字符，区分于app_desc</value>
        [DataMember(Name = "version_desc", EmitDefaultValue = false)]
        public string VersionDesc { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenMiniInnerversionAuditSubmitModel {\n");
            sb.Append("  AppCategoryIds: ").Append(AppCategoryIds).Append("\n");
            sb.Append("  AppDesc: ").Append(AppDesc).Append("\n");
            sb.Append("  AppEnglishName: ").Append(AppEnglishName).Append("\n");
            sb.Append("  AppLogo: ").Append(AppLogo).Append("\n");
            sb.Append("  AppName: ").Append(AppName).Append("\n");
            sb.Append("  AppOrigin: ").Append(AppOrigin).Append("\n");
            sb.Append("  AppSlogan: ").Append(AppSlogan).Append("\n");
            sb.Append("  AppVersion: ").Append(AppVersion).Append("\n");
            sb.Append("  BundleId: ").Append(BundleId).Append("\n");
            sb.Append("  LicenseInfo: ").Append(LicenseInfo).Append("\n");
            sb.Append("  Memo: ").Append(Memo).Append("\n");
            sb.Append("  MiniAppId: ").Append(MiniAppId).Append("\n");
            sb.Append("  MiniCategoryIds: ").Append(MiniCategoryIds).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  OutDoorPic: ").Append(OutDoorPic).Append("\n");
            sb.Append("  Pid: ").Append(Pid).Append("\n");
            sb.Append("  ScreenShotList: ").Append(ScreenShotList).Append("\n");
            sb.Append("  ServiceEmail: ").Append(ServiceEmail).Append("\n");
            sb.Append("  ServicePhone: ").Append(ServicePhone).Append("\n");
            sb.Append("  SpecialLicensePicList: ").Append(SpecialLicensePicList).Append("\n");
            sb.Append("  VersionDesc: ").Append(VersionDesc).Append("\n");
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
            return this.Equals(input as AlipayOpenMiniInnerversionAuditSubmitModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniInnerversionAuditSubmitModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniInnerversionAuditSubmitModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniInnerversionAuditSubmitModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AppCategoryIds == input.AppCategoryIds ||
                    (this.AppCategoryIds != null &&
                    this.AppCategoryIds.Equals(input.AppCategoryIds))
                ) && 
                (
                    this.AppDesc == input.AppDesc ||
                    (this.AppDesc != null &&
                    this.AppDesc.Equals(input.AppDesc))
                ) && 
                (
                    this.AppEnglishName == input.AppEnglishName ||
                    (this.AppEnglishName != null &&
                    this.AppEnglishName.Equals(input.AppEnglishName))
                ) && 
                (
                    this.AppLogo == input.AppLogo ||
                    (this.AppLogo != null &&
                    this.AppLogo.Equals(input.AppLogo))
                ) && 
                (
                    this.AppName == input.AppName ||
                    (this.AppName != null &&
                    this.AppName.Equals(input.AppName))
                ) && 
                (
                    this.AppOrigin == input.AppOrigin ||
                    (this.AppOrigin != null &&
                    this.AppOrigin.Equals(input.AppOrigin))
                ) && 
                (
                    this.AppSlogan == input.AppSlogan ||
                    (this.AppSlogan != null &&
                    this.AppSlogan.Equals(input.AppSlogan))
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
                    this.LicenseInfo == input.LicenseInfo ||
                    (this.LicenseInfo != null &&
                    this.LicenseInfo.Equals(input.LicenseInfo))
                ) && 
                (
                    this.Memo == input.Memo ||
                    (this.Memo != null &&
                    this.Memo.Equals(input.Memo))
                ) && 
                (
                    this.MiniAppId == input.MiniAppId ||
                    (this.MiniAppId != null &&
                    this.MiniAppId.Equals(input.MiniAppId))
                ) && 
                (
                    this.MiniCategoryIds == input.MiniCategoryIds ||
                    (this.MiniCategoryIds != null &&
                    this.MiniCategoryIds.Equals(input.MiniCategoryIds))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.OutDoorPic == input.OutDoorPic ||
                    (this.OutDoorPic != null &&
                    this.OutDoorPic.Equals(input.OutDoorPic))
                ) && 
                (
                    this.Pid == input.Pid ||
                    (this.Pid != null &&
                    this.Pid.Equals(input.Pid))
                ) && 
                (
                    this.ScreenShotList == input.ScreenShotList ||
                    this.ScreenShotList != null &&
                    input.ScreenShotList != null &&
                    this.ScreenShotList.SequenceEqual(input.ScreenShotList)
                ) && 
                (
                    this.ServiceEmail == input.ServiceEmail ||
                    (this.ServiceEmail != null &&
                    this.ServiceEmail.Equals(input.ServiceEmail))
                ) && 
                (
                    this.ServicePhone == input.ServicePhone ||
                    (this.ServicePhone != null &&
                    this.ServicePhone.Equals(input.ServicePhone))
                ) && 
                (
                    this.SpecialLicensePicList == input.SpecialLicensePicList ||
                    (this.SpecialLicensePicList != null &&
                    this.SpecialLicensePicList.Equals(input.SpecialLicensePicList))
                ) && 
                (
                    this.VersionDesc == input.VersionDesc ||
                    (this.VersionDesc != null &&
                    this.VersionDesc.Equals(input.VersionDesc))
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
                if (this.AppCategoryIds != null)
                {
                    hashCode = (hashCode * 59) + this.AppCategoryIds.GetHashCode();
                }
                if (this.AppDesc != null)
                {
                    hashCode = (hashCode * 59) + this.AppDesc.GetHashCode();
                }
                if (this.AppEnglishName != null)
                {
                    hashCode = (hashCode * 59) + this.AppEnglishName.GetHashCode();
                }
                if (this.AppLogo != null)
                {
                    hashCode = (hashCode * 59) + this.AppLogo.GetHashCode();
                }
                if (this.AppName != null)
                {
                    hashCode = (hashCode * 59) + this.AppName.GetHashCode();
                }
                if (this.AppOrigin != null)
                {
                    hashCode = (hashCode * 59) + this.AppOrigin.GetHashCode();
                }
                if (this.AppSlogan != null)
                {
                    hashCode = (hashCode * 59) + this.AppSlogan.GetHashCode();
                }
                if (this.AppVersion != null)
                {
                    hashCode = (hashCode * 59) + this.AppVersion.GetHashCode();
                }
                if (this.BundleId != null)
                {
                    hashCode = (hashCode * 59) + this.BundleId.GetHashCode();
                }
                if (this.LicenseInfo != null)
                {
                    hashCode = (hashCode * 59) + this.LicenseInfo.GetHashCode();
                }
                if (this.Memo != null)
                {
                    hashCode = (hashCode * 59) + this.Memo.GetHashCode();
                }
                if (this.MiniAppId != null)
                {
                    hashCode = (hashCode * 59) + this.MiniAppId.GetHashCode();
                }
                if (this.MiniCategoryIds != null)
                {
                    hashCode = (hashCode * 59) + this.MiniCategoryIds.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.OutDoorPic != null)
                {
                    hashCode = (hashCode * 59) + this.OutDoorPic.GetHashCode();
                }
                if (this.Pid != null)
                {
                    hashCode = (hashCode * 59) + this.Pid.GetHashCode();
                }
                if (this.ScreenShotList != null)
                {
                    hashCode = (hashCode * 59) + this.ScreenShotList.GetHashCode();
                }
                if (this.ServiceEmail != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceEmail.GetHashCode();
                }
                if (this.ServicePhone != null)
                {
                    hashCode = (hashCode * 59) + this.ServicePhone.GetHashCode();
                }
                if (this.SpecialLicensePicList != null)
                {
                    hashCode = (hashCode * 59) + this.SpecialLicensePicList.GetHashCode();
                }
                if (this.VersionDesc != null)
                {
                    hashCode = (hashCode * 59) + this.VersionDesc.GetHashCode();
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
